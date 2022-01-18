import hashlib
import logging
import os
import re
import select
import shutil
import signal
import socket
import sys
import threading
from concurrent.futures import ALL_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

import msgpack
import tqdm
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import PromptSession

from utils.constants import (
    CLIENT_RECV_PORT,
    CLIENT_SEND_PORT,
    FILE_BUFFER_LEN,
    FMT,
    HEADER_MSG_LEN,
    HEADER_TYPE_LEN,
    RECV_FOLDER_PATH,
    SERVER_RECV_PORT,
    SHARE_FOLDER_PATH,
)
from utils.exceptions import ExceptionCode, RequestException
from utils.helpers import (
    display_share_dict,
    find_file,
    get_file_hash,
    get_files_in_dir,
    get_unique_filename,
    path_to_dict,
)
from utils.types import DBData, DirData, FileMetadata, FileRequest, HeaderCode, UpdateHashParams

SERVER_IP = input("Enter SERVER IP: ")
SERVER_ADDR = (SERVER_IP, SERVER_RECV_PORT)
CLIENT_IP = socket.gethostbyname(socket.gethostname())

logging.basicConfig(filename=f"/logs/client_{CLIENT_IP}.log", level=logging.DEBUG)

client_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # to connect to main server
client_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # to receive new connections
client_send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
client_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
client_send_socket.bind((CLIENT_IP, CLIENT_SEND_PORT))
client_recv_socket.bind((CLIENT_IP, CLIENT_RECV_PORT))
client_send_socket.connect((SERVER_IP, SERVER_RECV_PORT))
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


def request_file(file_requested: DirData, client_peer_socket: socket.socket) -> str:
    file_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    file_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    file_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
    file_recv_socket.bind((CLIENT_IP, 0))
    file_recv_socket.listen()
    file_recv_port = file_recv_socket.getsockname()[1]

    request_hash = file_requested["hash"] is None
    file_request: FileRequest = {
        "port": file_recv_port,
        "filepath": file_requested["path"],
        "request_hash": request_hash,
    }

    file_req_bytes = msgpack.packb(file_request)
    file_req_header = (
        f"{HeaderCode.FILE_REQUEST.value}{len(file_req_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
    )
    client_peer_socket.send(file_req_header + file_req_bytes)

    try:
        res_type = client_peer_socket.recv(HEADER_TYPE_LEN).decode(FMT)
        match res_type:
            case HeaderCode.FILE_REQUEST.value:
                sender, _ = file_recv_socket.accept()
                logging.debug(msg=f"Sender tried to connect: {sender.getpeername()}")
                res_type = sender.recv(HEADER_TYPE_LEN).decode(FMT)
                if res_type == HeaderCode.FILE.value:
                    file_header_len = int(sender.recv(HEADER_MSG_LEN).decode(FMT))
                    file_header: FileMetadata = msgpack.unpackb(sender.recv(file_header_len))
                    logging.debug(msg=f"receiving file with metadata {file_header}")
                    # Check if free disk space is available
                    if shutil.disk_usage(str(RECV_FOLDER_PATH)).free > file_header["size"]:
                        write_path: Path = get_unique_filename(
                            RECV_FOLDER_PATH / file_header["name"]
                        )

                        try:
                            write_path.parent.mkdir(parents=True, exist_ok=True)
                            file_to_write = write_path.open("wb")
                            logging.debug(f"Creating and writing to {write_path}")
                            try:
                                byte_count = 0
                                hash = hashlib.sha1()
                                with tqdm.tqdm(
                                    total=file_header["size"],
                                    desc=f"Receiving {file_header['name']}",
                                    unit="B",
                                    unit_scale=True,
                                    unit_divisor=1024,
                                ) as progress:
                                    while True:
                                        file_bytes_read: bytes = sender.recv(FILE_BUFFER_LEN)
                                        hash.update(file_bytes_read)
                                        num_bytes_read = len(file_bytes_read)
                                        byte_count += num_bytes_read
                                        file_to_write.write(file_bytes_read)
                                        progress.update(num_bytes_read)
                                        logging.debug(
                                            msg=f"Received chunk of size {num_bytes_read}, received {byte_count} of {file_header['size']}"
                                        )
                                        if num_bytes_read == 0:
                                            break
                                    file_to_write.close()
                                    received_hash = hash.hexdigest()
                                    if (request_hash and received_hash == file_header["hash"]) or (
                                        received_hash == file_requested["hash"]
                                    ):
                                        return "Succesfully received 1 file"
                                    else:
                                        logging.error(
                                            msg=f"Failed integrity check for file {file_header['name']}"
                                        )
                                        return "Integrity check failed"
                            except Exception as e:
                                logging.error(e)
                                return "File received but failed to save"
                        except Exception as e:
                            logging.error(e)
                            return "Unable to write file"
                    else:
                        logging.error(
                            msg=f"Not enough space to receive file {file_header['name']}, {file_header['size']}"
                        )
                        return "Not enough space to receive file"
                else:
                    raise RequestException(
                        f"Sender sent invalid message type in header: {res_type}",
                        ExceptionCode.INVALID_HEADER,
                    )
            case HeaderCode.ERROR.value:
                res_len = int(client_peer_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                res = client_peer_socket.recv(res_len)
                err: RequestException = msgpack.unpackb(
                    res,
                    object_hook=RequestException.from_dict,
                    raw=False,
                )
                raise err
            case _:
                err = RequestException(
                    f"Invalid message type in header: {res_type}",
                    ExceptionCode.INVALID_HEADER,
                )
                raise err
    except UnicodeDecodeError as e:
        logging.error(f"UnicodeDecodeError: {e}")
        raise RequestException("Invalid message type in header", ExceptionCode.INVALID_HEADER)


def send_handler() -> None:
    global client_send_socket
    with patch_stdout():
        mode_prompt: PromptSession = PromptSession(
            "\nMODE : \n1. Browse files\n2. Send message\n3. Exit\n"
        )
        recipient_prompt: PromptSession = PromptSession("Enter username :")
        search_prompt: PromptSession = PromptSession("Enter search term :")
        while True:
            mode = mode_prompt.prompt()
            match mode:
                case "1":
                    # search_term = search_prompt.prompt()
                    # search_res_list = [
                    #     r"(\S+)$",
                    #     r"'(.+)'$",
                    #     r'"(.+)"$',
                    # ]

                    # searchquery = ""
                    # for r in search_res_list:
                    #     match_res = re.match(r, search_term)
                    #     if match_res:
                    #         searchquery = match_res.group(1)
                    #         break
                    # if searchquery:
                    # searchquery_bytes = searchquery.encode(FMT)
                    searchquery_bytes = b" "
                    search_header = f"{HeaderCode.FILE_SEARCH.value}{len(searchquery_bytes):<{HEADER_MSG_LEN}}".encode(
                        FMT
                    )
                    client_send_socket.send(search_header + searchquery_bytes)
                    response_header_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
                    if response_header_type == HeaderCode.FILE_SEARCH.value:
                        response_len = int(
                            client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
                        )
                        browse_files: list[DBData] = msgpack.unpackb(
                            client_send_socket.recv(response_len),
                        )
                        # search_result = [
                        #     FileSearchResult(*result) for result in browse_files
                        # ]
                        if len(browse_files):
                            for index, data in enumerate(browse_files):
                                print(f"{index + 1}. {data['uname']}")

                            # for i, res in enumerate(search_result):
                            #     print(f"{i+1} PATH: {res.filepath} \n\t USER: {res.uname}")

                            uname_choice_prompt: PromptSession = PromptSession(
                                "Enter uname to browse: "
                            )
                            uname_choice: str = uname_choice_prompt.prompt()

                            if not uname_choice.isdigit() or not (
                                1 <= int(uname_choice) <= len(browse_files)
                            ):
                                continue
                            selected_user = browse_files[int(uname_choice) - 1]
                            files_requested = selected_user["share"]
                            print(selected_user["uname"] + "/share/")
                            display_share_dict(files_requested, 1)

                            file_choice_prompt: PromptSession = PromptSession(
                                "Enter filepath to download: "
                            )
                            file_choice: str = file_choice_prompt.prompt()
                            file_item = find_file(selected_user["share"], file_choice)

                            if file_item is None:
                                print("File path not found")
                                continue

                            uname_bytes = selected_user["uname"].encode(FMT)
                            request_header = f"{HeaderCode.REQUEST_IP.value}{len(uname_bytes):<{HEADER_MSG_LEN}}".encode(
                                FMT
                            )
                            logging.debug(
                                msg=f"Sent packet {(request_header + uname_bytes).decode(FMT)}"
                            )
                            client_send_socket.send(request_header + uname_bytes)
                            res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
                            logging.debug(msg=f"Response type: {res_type}")
                            response_length = int(
                                client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
                            )
                            peer_ip_bytes: bytes = client_send_socket.recv(response_length)

                            if res_type == HeaderCode.REQUEST_IP.value:
                                peer_ip: str = peer_ip_bytes.decode(FMT)

                                with ThreadPoolExecutor() as executor:
                                    if file_item["type"] == "file":
                                        executor.submit(
                                            req_file_worker,
                                            file_item,
                                            peer_ip,
                                        )
                                        # req_file_thread = threading.Thread(
                                        #     target=req_file_worker,
                                        #     args=(
                                        #         file_item,
                                        #         peer_ip,
                                        #     ),
                                        # )
                                        # req_file_thread.start()
                                    else:
                                        files_to_request: list[DirData] = []
                                        get_files_in_dir(
                                            file_item["children"],
                                            files_to_request,
                                        )
                                        futures = executor.map(
                                            req_file_worker,
                                            files_to_request,
                                            [peer_ip] * len(files_to_request),
                                        )
                            elif res_type == HeaderCode.ERROR.value:
                                res_len = int(
                                    client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
                                )
                                res = client_send_socket.recv(res_len)
                                error: RequestException = msgpack.unpackb(
                                    res,
                                    object_hook=RequestException.from_dict,
                                    raw=False,
                                )
                                logging.error(msg=error)
                            else:
                                logging.error(f"Invalid message type in header: {res_type}")

                        else:
                            print("No results found")
                    else:
                        logging.error("Error occured while searching for files")
                case "2":
                    recipient = recipient_prompt.prompt()
                    if recipient:
                        recipient = recipient.encode(FMT)
                        request_header = f"{HeaderCode.REQUEST_IP.value}{len(recipient):<{HEADER_MSG_LEN}}".encode(
                            FMT
                        )
                        logging.debug(msg=f"Sent packet {(request_header + recipient).decode(FMT)}")
                        client_send_socket.send(request_header + recipient)
                        res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
                        logging.debug(msg=f"Response type: {res_type}")
                        response_length = int(
                            client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
                        )
                        peer_ip = client_send_socket.recv(response_length)

                        if res_type == HeaderCode.REQUEST_IP.value:
                            recipient_addr: str = peer_ip.decode(FMT)
                            logging.debug(msg=f"Response: {recipient_addr}")
                            client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            client_peer_socket.connect((recipient_addr, CLIENT_RECV_PORT))
                            while True:
                                msg_prompt: PromptSession = PromptSession(
                                    f"\nEnter message for {recipient.decode(FMT)}: "
                                )
                                msg = msg_prompt.prompt()
                                if len(msg):
                                    # filere = "\!send ()"
                                    msg.strip().split()
                                    send_res_list = [
                                        r"!send (\S+)$",
                                        r"!send '(.+)'$",
                                        r'!send "(.+)"$',
                                    ]

                                    filename = ""
                                    for r in send_res_list:
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
                                            filemetadata_bytes = msgpack.packb(filemetadata)
                                            logging.debug(filemetadata_bytes)
                                            filesend_header = f"{HeaderCode.FILE.value}{len(filemetadata_bytes):<{HEADER_MSG_LEN}}".encode(
                                                FMT
                                            )
                                            try:
                                                file_to_send = filepath.open(mode="rb")
                                                logging.debug(
                                                    f"Sending file {filename} to {recipient.decode(FMT)}"
                                                )
                                                client_peer_socket.send(
                                                    filesend_header + filemetadata_bytes
                                                )
                                                with tqdm.tqdm(
                                                    total=filemetadata["size"],
                                                    desc=f"Sending {str(filepath)}",
                                                    unit="B",
                                                    unit_scale=True,
                                                    unit_divisor=1024,
                                                ) as progress:
                                                    total_bytes_read = 0
                                                    while total_bytes_read != filemetadata["size"]:
                                                        bytes_read = file_to_send.read(
                                                            FILE_BUFFER_LEN
                                                        )
                                                        client_peer_socket.sendall(bytes_read)
                                                        num_bytes = len(bytes_read)
                                                        total_bytes_read += num_bytes
                                                        progress.update(num_bytes)
                                                    progress.close()
                                                    print("File Sent")
                                                    file_to_send.close()
                                            except Exception as e:
                                                logging.error(f"File Sending failed: {e}")
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
                        elif res_type == HeaderCode.ERROR.value:
                            err: RequestException = msgpack.unpackb(
                                peer_ip,
                                object_hook=RequestException.from_dict,
                                raw=False,
                            )
                            logging.error(msg=err)
                        else:
                            logging.error(f"Invalid message type in header: {res_type}")
                case "3":
                    if os.name == "nt":
                        os._exit(0)
                    else:
                        os.kill(os.getpid(), signal.SIGINT)


def req_file_thread_target(file_item, peer_ip):
    try:
        with ThreadPoolExecutor() as executor:
            files_to_request: list[DirData] = []
            get_files_in_dir(
                file_item["children"],
                files_to_request,
            )
            futures = executor.map(
                req_file_worker,
                files_to_request,
                [peer_ip] * len(files_to_request),
            )
            wait(futures, return_when=ALL_COMPLETED)
            # executor.shutdown(wait=True)
            # for file in files_to_request:
            #     executor.submit(req_file_worker, file, peer_ip)
    except Exception as e:
        logging.error(e.with_traceback(e.__traceback__))


def req_file_worker(file_item: DirData, peer_ip: str):
    client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_peer_socket.connect((peer_ip, CLIENT_RECV_PORT))
    request_file(file_item, client_peer_socket)


def send_file(filepath: Path, requester: tuple[str, int], request_hash: bool) -> None:
    file_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    file_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    file_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
    file_send_socket.connect(requester)
    hash = ""
    # compression = CompressionMethod.NONE

    # file_size = filepath.stat().st_size
    # if file_size < COMPRESSION_THRESHOLD:
    #     compression = CompressionMethod.ZSTD
    #     compressor = zstd.ZstdCompressor()
    #     with filepath.open(mode="rb") as uncompressed_file:
    #         with compressor.stream_writer(uncompressed_file) as writer:
    #             pass
    if request_hash:
        hash = get_file_hash(str(filepath))

    filemetadata: FileMetadata = {
        "name": str(filepath).removeprefix(str(SHARE_FOLDER_PATH) + "/"),
        "size": filepath.stat().st_size,
        "hash": hash if request_hash else None,
        # "compression": compression,
    }

    logging.debug(filemetadata)
    filemetadata_bytes = msgpack.packb(filemetadata)
    logging.debug(filemetadata_bytes)
    filesend_header = f"{HeaderCode.FILE.value}{len(filemetadata_bytes):<{HEADER_MSG_LEN}}".encode(
        FMT
    )

    try:
        file_to_send = filepath.open(mode="rb")
        logging.debug(f"Sending file {filemetadata['name']} to {requester}")
        file_send_socket.send(filesend_header + filemetadata_bytes)
        with tqdm.tqdm(
            total=filemetadata["size"],
            desc=f"Sending {str(filepath)}",
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
        ) as progress:
            total_bytes_read = 0
            while total_bytes_read != filemetadata["size"]:
                bytes_read = file_to_send.read(FILE_BUFFER_LEN)
                num_bytes = file_send_socket.send(bytes_read)
                total_bytes_read += num_bytes
                progress.update(num_bytes)
                logging.debug(
                    f"Sent chunk of size {num_bytes}, total {total_bytes_read} of {filemetadata['size']}"
                )
            progress.close()
            print("File Sent")
            file_to_send.close()
            file_send_socket.close()
        if request_hash:
            update_hash_params: UpdateHashParams = {
                "filepath": str(filepath).removeprefix(str(SHARE_FOLDER_PATH) + "/"),
                "hash": hash,
            }
            update_hash_bytes = msgpack.packb(update_hash_params)
            update_hash_header = (
                f"{HeaderCode.UPDATE_HASH.value}{len(update_hash_bytes):<{HEADER_MSG_LEN}}".encode(
                    FMT
                )
            )
            client_send_socket.send(update_hash_header + update_hash_bytes)
    except Exception as e:
        logging.error(f"File Sending failed: {e}")


def receive_msg(socket: socket.socket) -> str:
    logging.debug(f"Receiving from {socket.getpeername()}")
    message_type = socket.recv(HEADER_TYPE_LEN).decode(FMT)
    if not len(message_type):
        raise RequestException(
            msg=f"Peer at {socket.getpeername()} closed the connection",
            code=ExceptionCode.DISCONNECT,
        )
    elif message_type not in [
        HeaderCode.MESSAGE.value,
        HeaderCode.FILE.value,
        HeaderCode.FILE_REQUEST.value,
    ]:
        raise RequestException(
            msg=f"Invalid message type in header. Received [{message_type}]",
            code=ExceptionCode.INVALID_HEADER,
        )
    else:
        match message_type:
            case HeaderCode.FILE.value:
                file_header_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                file_header: FileMetadata = msgpack.unpackb(socket.recv(file_header_len))
                logging.debug(msg=f"receiving file with metadata {file_header}")
                write_path: Path = get_unique_filename(RECV_FOLDER_PATH / file_header["name"])
                try:
                    file_to_write = open(str(write_path), "wb")
                    logging.debug(f"Creating and writing to {write_path}")
                    try:
                        byte_count = 0
                        with tqdm.tqdm(
                            total=file_header["size"],
                            desc=f"Receiving {file_header['name']}",
                            unit="B",
                            unit_scale=True,
                            unit_divisor=1024,
                        ) as progress:
                            while byte_count != file_header["size"]:
                                file_bytes_read: bytes = socket.recv(FILE_BUFFER_LEN)
                                byte_count += len(file_bytes_read)
                                file_to_write.write(file_bytes_read)
                                progress.update(len(file_bytes_read))
                            file_to_write.close()
                            return "Succesfully received 1 file"
                    except Exception as e:
                        logging.error(e)
                        return "File received but failed to save"
                except Exception as e:
                    logging.error(e)
                    return "Unable to write file"
            case HeaderCode.FILE_REQUEST.value:
                req_header_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                file_req_header: FileRequest = msgpack.unpackb(socket.recv(req_header_len))
                logging.debug(msg=f"Received request: {file_req_header}")
                requested_file_path = SHARE_FOLDER_PATH / file_req_header["filepath"]
                if requested_file_path.is_file():
                    socket.send(HeaderCode.FILE_REQUEST.value.encode(FMT))
                    send_file_thread = threading.Thread(
                        target=send_file,
                        args=(
                            requested_file_path,
                            (socket.getpeername()[0], file_req_header["port"]),
                            file_req_header["request_hash"],
                        ),
                    )
                    send_file_thread.start()
                    return "File requested by user"
                else:
                    # TODO: Update file info on server
                    raise RequestException(
                        f"Requested file {file_req_header['filepath']} is not available",
                        ExceptionCode.NOT_FOUND,
                    )
            case _:
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
                    msg=("Accepted new connection from" f" {peer_addr[0]}:{peer_addr[1]}"),
                )
                try:
                    connected.append(peer_socket)
                    lookup = peer_addr[0].encode(FMT)
                    header = (
                        f"{HeaderCode.REQUEST_UNAME.value}{len(lookup):<{HEADER_MSG_LEN}}".encode(
                            FMT
                        )
                    )
                    logging.debug(msg=f"Sending packet {(header + lookup).decode(FMT)}")
                    client_send_socket.send(header + lookup)
                    res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
                    if res_type not in [
                        HeaderCode.REQUEST_UNAME.value,
                        HeaderCode.ERROR.value,
                    ]:
                        raise RequestException(
                            msg="Invalid message type in header",
                            code=ExceptionCode.INVALID_HEADER,
                        )
                    else:
                        response_length = int(
                            client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
                        )
                        response = client_send_socket.recv(response_length)
                        if res_type == HeaderCode.REQUEST_UNAME.value:
                            username = response.decode(FMT)
                            print(f"User {username} is trying to send a message")
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


def excepthook(args: threading.ExceptHookArgs) -> None:
    logging.fatal(msg=args)
    logging.fatal(msg=args.exc_traceback)


if __name__ == "__main__":
    try:
        while prompt_username() != HeaderCode.NEW_CONNECTION.value:
            error_len = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
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
        print("Successfully registered")
        share_data = msgpack.packb(path_to_dict(SHARE_FOLDER_PATH)["children"])
        share_data_header = (
            f"{HeaderCode.SHARE_DATA.value}{len(share_data):<{HEADER_MSG_LEN}}".encode(FMT)
        )
        client_send_socket.sendall(share_data_header + share_data)

        threading.excepthook = excepthook
        send_thread = threading.Thread(target=send_handler)
        receive_thread = threading.Thread(target=receive_handler)
        send_thread.start()
        receive_thread.start()
        send_thread.join()
        receive_thread.join()
    except (KeyboardInterrupt, EOFError, SystemExit):
        sys.exit(0)
    except:
        logging.fatal(msg=sys.exc_info()[0])
        sys.exit(1)
