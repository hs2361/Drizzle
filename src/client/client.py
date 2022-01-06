import logging
import os
import re
import select
import signal
import socket
import sys
import threading
from pathlib import Path

import msgpack
import tqdm
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import PromptSession

from utils.exceptions import ExceptionCode, RequestException
from utils.headers import FileMetadata, HeaderCode

HEADER_TYPE_LEN = 1
HEADER_MSG_LEN = 7
SERVER_IP = input("Enter SERVER IP: ")
SERVER_PORT = 1234
SERVER_ADDR = (SERVER_IP, SERVER_PORT)
FMT = "utf-8"
CLIENT_IP = socket.gethostbyname(socket.gethostname())
CLIENT_SEND_PORT = 5678
CLIENT_RECV_PORT = 4321
SHARE_FOLDER_PATH = Path("/Drizzle/share")
RECV_FOLDER_PATH = Path("/Drizzle/downloads")
FILE_BUFFER_LEN = 4096

logging.basicConfig(
    filename=f"/logs/client_{CLIENT_IP}.log", level=logging.DEBUG
)

client_send_socket = socket.socket(
    socket.AF_INET, socket.SOCK_STREAM
)  # to connect to main server
client_recv_socket = socket.socket(
    socket.AF_INET, socket.SOCK_STREAM
)  # to receive new connections
client_send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_send_socket.bind((CLIENT_IP, CLIENT_SEND_PORT))
client_recv_socket.bind((CLIENT_IP, CLIENT_RECV_PORT))
client_send_socket.connect((SERVER_IP, SERVER_PORT))
client_recv_socket.listen(5)
connected = [client_recv_socket]


def prompt_username() -> str:
    my_username = input("Enter username: ")
    username = my_username.encode(FMT)
    username_header = f"{HeaderCode.NEW_CONNECTION.value}{len(username):<{HEADER_MSG_LEN}}".encode(
        FMT
    )
    client_send_socket.send(username_header + username)
    type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
    return type


def send_handler() -> None:
    global client_send_socket
    with patch_stdout():
        recipient_prompt: PromptSession = PromptSession(
            "\nEnter recipient's username: "
        )
        while True:
            recipient = recipient_prompt.prompt()
            if recipient == "!exit":
                if os.name == "nt":
                    os._exit(0)
                else:
                    os.kill(os.getpid(), signal.SIGINT)
            if recipient:
                recipient = recipient.encode(FMT)
                request_header = f"{HeaderCode.REQUEST_UNAME.value}{len(recipient):<{HEADER_MSG_LEN}}".encode(
                    FMT
                )
                logging.debug(
                    msg=f"Sent packet {(request_header + recipient).decode(FMT)}"
                )
                client_send_socket.send(request_header + recipient)
                res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
                logging.debug(msg=f"Response type: {res_type}")
                response_length = int(
                    client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
                )
                response = client_send_socket.recv(response_length)
                if res_type == HeaderCode.REQUEST_UNAME.value:
                    recipient_addr: str = response.decode(FMT)
                    logging.debug(msg=f"Response: {recipient_addr}")
                    client_peer_socket = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM
                    )
                    client_peer_socket.connect(
                        (recipient_addr, CLIENT_RECV_PORT)
                    )
                    while True:
                        msg_prompt: PromptSession = PromptSession(
                            f"\nEnter message for {recipient.decode(FMT)}: "
                        )
                        msg = msg_prompt.prompt()
                        if len(msg):
                            # filere = "\!send ()"
                            msg.strip().split()
                            res = [
                                r"!send (\S+)$",
                                r"!send '(.+)'$",
                                r'!send "(.+)"$',
                            ]
                            filename = ""
                            for r in res:
                                match_res = re.match(r, msg)
                                if match_res:
                                    filename = match_res.group(1)
                                    break
                            if filename:
                                filepath: Path = SHARE_FOLDER_PATH / filename
                                logging.debug(f"{filepath} chosen to send")
                                if filepath.exists() and filepath.is_file():
                                    filemetadata: FileMetadata = {
                                        "name": filename.split("/")[-1],
                                        "size": filepath.stat().st_size,
                                    }
                                    logging.debug(filemetadata)
                                    filemetadata_bytes = msgpack.packb(
                                        filemetadata
                                    )
                                    logging.debug(filemetadata_bytes)
                                    filesend_header = f"{HeaderCode.FILE.value}{len(filemetadata_bytes):<{HEADER_MSG_LEN}}".encode(
                                        FMT
                                    )
                                    try:
                                        file_to_send = filepath.open(mode="rb")
                                        logging.debug(
                                            f"Sending file {filename} to {recipient.decode(FMT)}"
                                        )
                                        client_peer_socket.send(filesend_header)
                                        client_peer_socket.send(
                                            filemetadata_bytes
                                        )
                                        progress = tqdm.tqdm(
                                            range(filemetadata["size"]),
                                            f"Sending {str(filepath)}",
                                            unit="B",
                                            unit_scale=True,
                                            unit_divisor=1024,
                                            colour="green",
                                        )
                                        total_bytes_read = 0
                                        while True:
                                            bytes_read = file_to_send.read(
                                                FILE_BUFFER_LEN
                                            )
                                            client_peer_socket.sendall(
                                                bytes_read
                                            )
                                            total_bytes_read += len(bytes_read)
                                            progress.update(len(bytes_read))
                                            if (
                                                total_bytes_read
                                                == filemetadata["size"]
                                            ):
                                                progress.close()
                                                break
                                        print("File Sent")
                                        file_to_send.close()
                                    except Exception as e:
                                        logging.error(
                                            f"File Sending failed: {e}"
                                        )
                                else:
                                    logging.error(f"{filepath} not found")
                                    print(
                                        f"Unable to perform send request, ensure that the file is available in {SHARE_FOLDER_PATH}"
                                    )
                            else:
                                msg = msg.encode(FMT)
                                if msg == b"!exit":
                                    break
                                header = f"{HeaderCode.MESSAGE.value}{len(msg):<{HEADER_MSG_LEN}}".encode(
                                    FMT
                                )
                                client_peer_socket.send(header + msg)
                if res_type == HeaderCode.ERROR.value:
                    err: RequestException = msgpack.unpackb(
                        response,
                        object_hook=RequestException.from_dict,
                        raw=False,
                    )
                    logging.error(msg=err)


def get_unique_filename(path: Path) -> Path:
    filename, extension = path.stem, path.suffix
    counter = 1

    while path.exists():
        path = RECV_FOLDER_PATH / Path(
            filename + "_" + str(counter) + extension
        )
        counter += 1

    logging.debug(f"unique file name is {path}")
    return path


def receive_msg(socket: socket.socket) -> str:
    logging.debug(f"Receiving from {socket.getpeername()}")
    message_type = socket.recv(HEADER_TYPE_LEN).decode(FMT)
    if not len(message_type):
        raise RequestException(
            msg=f"Peer at {socket.getpeername()} closed the connection",
            code=ExceptionCode.DISCONNECT,
        )
    elif message_type not in [HeaderCode.MESSAGE.value, HeaderCode.FILE.value]:
        raise RequestException(
            msg=f"Invalid message type in header. Received [{message_type}]",
            code=ExceptionCode.INVALID_HEADER,
        )
    else:
        if message_type == HeaderCode.FILE.value:
            file_header_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
            file_header: FileMetadata = msgpack.unpackb(
                socket.recv(file_header_len)
            )
            logging.debug(msg=f"receiving file with metadata {file_header}")
            write_path: Path = get_unique_filename(
                RECV_FOLDER_PATH / file_header["name"]
            )
            try:
                file_to_write = open(str(write_path), "wb")
                logging.debug(f"Creating and writing to {write_path}")
                try:
                    byte_count = 0
                    progress = tqdm.tqdm(
                        range(file_header["size"]),
                        f"Receiving {file_header['name']}",
                        unit="B",
                        unit_scale=True,
                        unit_divisor=1024,
                    )
                    while True:
                        file_bytes_read: bytes = socket.recv(FILE_BUFFER_LEN)
                        byte_count += len(file_bytes_read)
                        file_to_write.write(file_bytes_read)
                        progress.update(len(file_bytes_read))
                        if byte_count == file_header["size"]:
                            progress.close()
                            break
                    file_to_write.close()
                    return "Succesfully received 1 file"
                except Exception as e:
                    logging.error(e)
                    return "File received but failed to save"
            except Exception as e:
                logging.error(e)
                return "Unable to write file"
        else:
            message_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
            return socket.recv(message_len).decode(FMT)


def receive_handler() -> None:
    global client_send_socket
    global client_recv_socket
    peers: dict[str, str] = {}

    while True:
        read_sockets: list[socket.socket]
        read_sockets, _, __ = select.select(connected, [], [], 1)
        for notified_socket in read_sockets:
            if notified_socket == client_recv_socket:
                peer_socket, peer_addr = client_recv_socket.accept()
                logging.debug(
                    msg=(
                        "Accepted new connection from"
                        f" {peer_addr[0]}:{peer_addr[1]}"
                    ),
                )
                try:
                    connected.append(peer_socket)
                    lookup: bytes = peer_addr[0].encode(FMT)
                    header = f"{HeaderCode.LOOKUP_ADDRESS.value}{len(lookup):<{HEADER_MSG_LEN}}".encode(
                        FMT
                    )
                    logging.debug(
                        msg=f"Sending packet {(header + lookup).decode(FMT)}"
                    )
                    client_send_socket.send(header + lookup)
                    res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(
                        FMT
                    )
                    if res_type not in [
                        HeaderCode.LOOKUP_ADDRESS.value,
                        HeaderCode.ERROR.value,
                    ]:
                        raise RequestException(
                            msg="Invalid message type in header",
                            code=ExceptionCode.INVALID_HEADER,
                        )
                    else:
                        response_length = int(
                            client_send_socket.recv(HEADER_MSG_LEN)
                            .decode(FMT)
                            .strip()
                        )
                        response = client_send_socket.recv(response_length)
                        if res_type == HeaderCode.LOOKUP_ADDRESS.value:
                            username = response.decode(FMT)
                            print(
                                f"User {username} is trying to send a message"
                            )
                            peers[peer_addr[0]] = username
                        else:
                            exception = msgpack.unpackb(
                                response,
                                object_hook=RequestException.from_dict,
                                raw=False,
                            )
                            logging.error(msg=exception)
                            raise exception
                except RequestException as e:
                    logging.error(msg=e)
                    break
            else:
                try:
                    msg: str = receive_msg(notified_socket)
                    username = peers[notified_socket.getpeername()[0]]
                    print(f"{username} > {msg}")
                except RequestException as e:
                    if e.code == ExceptionCode.DISCONNECT:
                        try:
                            connected.remove(notified_socket)
                        except ValueError:
                            logging.info("already removed")
                    logging.error(msg=f"Exception: {e.msg}")
                    break


def excepthook(args: threading.ExceptHookArgs):
    logging.fatal(msg=args)
    logging.fatal(msg=args.exc_traceback)


if __name__ == "__main__":
    try:
        while prompt_username() != HeaderCode.NEW_CONNECTION.value:
            error_len = int(
                client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
            )
            error = client_send_socket.recv(error_len)
            exception: RequestException = msgpack.unpackb(
                error, object_hook=RequestException.from_dict, raw=False
            )
            if exception.code == ExceptionCode.USER_EXISTS:
                logging.error(msg=exception.msg)
                print("Sorry that username is taken, please choose another one")
            else:
                logging.fatal(msg=exception.msg)
                print("Sorry something went wrong")
                client_send_socket.close()
                client_recv_socket.close()
                sys.exit(1)
        else:
            print("Successfully registered")
        threading.excepthook = excepthook
        send_thread = threading.Thread(target=send_handler)
        receive_thread = threading.Thread(target=receive_handler)
        send_thread.start()
        receive_thread.start()
    except (KeyboardInterrupt, EOFError, SystemExit):
        sys.exit(0)
    except:
        logging.fatal(msg=sys.exc_info()[0])
        sys.exit(1)
