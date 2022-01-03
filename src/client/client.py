import logging
import select
import socket
import sys
import threading

import msgpack
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import PromptSession

from exceptions import ExceptionCode, RequestException

HEADER_TYPE_LEN = 1
HEADER_MSG_LEN = 7
SERVER_IP = input("Enter SERVER IP: ")
SERVER_PORT = 1234
SERVER_ADDR = (SERVER_IP, SERVER_PORT)
FMT = "utf-8"
CLIENT_IP = socket.gethostbyname(socket.gethostname())
CLIENT_SEND_PORT = 5678
CLIENT_RECV_PORT = 4321

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
    username_header = f"n{len(username):<{HEADER_MSG_LEN}}".encode(FMT)
    client_send_socket.send(username_header + username)
    type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
    return type


def send_handler():
    global client_send_socket
    with patch_stdout():
        recipient_prompt = PromptSession("\nEnter recipient's username: ")
        while True:
            recipient = recipient_prompt.prompt()
            if recipient:
                recipient = recipient.encode(FMT)
                request_header = f"r{len(recipient):<{HEADER_MSG_LEN}}".encode(
                    FMT
                )
                logging.debug(
                    f"Sent packet {(request_header + recipient).decode(FMT)}"
                )
                client_send_socket.send(request_header + recipient)
                res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
                logging.log(
                    level=logging.DEBUG, msg=f"Response type: {res_type}"
                )
                response_length = int(
                    client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
                )
                response = client_send_socket.recv(response_length)
                if res_type == "r":
                    recipient_addr: str = response.decode(FMT)
                    logging.log(
                        level=logging.DEBUG, msg=f"Response: {recipient_addr}"
                    )
                    client_peer_socket = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM
                    )
                    client_peer_socket.connect(
                        (recipient_addr, CLIENT_RECV_PORT)
                    )
                    while True:
                        msg_prompt = PromptSession(
                            f"\nEnter message for {recipient.decode(FMT)}: "
                        )
                        msg = msg_prompt.prompt()
                        msg = msg.encode(FMT)
                        if msg == b"!exit":
                            break
                        header = f"m{len(msg):<{HEADER_MSG_LEN}}".encode(FMT)
                        client_peer_socket.send(header + msg)
                if res_type == "e":
                    err: RequestException = msgpack.unpackb(
                        response,
                        object_hook=RequestException.from_dict,
                        raw=False,
                    )
                    logging.log(level=logging.ERROR, msg=err)


def receive_msg(socket: socket.socket) -> str:
    message_type = socket.recv(HEADER_TYPE_LEN).decode(FMT)
    if not len(message_type):
        raise RequestException(
            msg=f"Peer at {socket.getpeername()} closed the connection",
            code=ExceptionCode.DISCONNECT,
        )
    elif message_type != "m":
        raise RequestException(
            msg="Invalid message type in header",
            code=ExceptionCode.INVALID_HEADER,
        )
    else:
        message_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
        return socket.recv(message_len).decode(FMT)


def receive_handler():
    global client_send_socket
    global client_recv_socket
    peers: dict[str, str] = {}

    while True:
        read_sockets: list[socket.socket]
        read_sockets, _, __ = select.select(connected, [], [], 1)
        for notified_socket in read_sockets:
            if notified_socket == client_recv_socket:
                peer_socket, peer_addr = client_recv_socket.accept()
                logging.log(
                    level=logging.DEBUG,
                    msg=(
                        "Accepted new connection from"
                        f" {peer_addr[0]}:{peer_addr[1]}"
                    ),
                )
                try:
                    connected.append(peer_socket)
                    lookup: bytes = peer_addr[0].encode(FMT)
                    header = f"l{len(lookup):<{HEADER_MSG_LEN}}".encode(FMT)
                    logging.debug(
                        f"Sending packet {(header + lookup).decode(FMT)}"
                    )
                    client_send_socket.send(header + lookup)
                    res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(
                        FMT
                    )
                    if res_type not in ["l", "e"]:
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
                        if res_type == "l":
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
                            logging.error(exception)
                            raise exception
                except RequestException as e:
                    logging.log(level=logging.ERROR, msg=e)
                    break
            else:
                try:
                    msg: str = receive_msg(notified_socket)
                    username = peers[notified_socket.getpeername()[0]]
                    print(f"{username} says: {msg}")
                except RequestException as e:
                    if e.code == ExceptionCode.DISCONNECT:
                        try:
                            connected.remove(notified_socket)
                        except ValueError:
                            logging.info("already removed")
                    logging.log(level=logging.ERROR, msg=f"Exception: {e.msg}")
                    break


if __name__ == "__main__":
    while prompt_username() != "n":
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
    send_thread = threading.Thread(target=send_handler)
    receive_thread = threading.Thread(target=receive_handler)
    send_thread.start()
    receive_thread.start()
