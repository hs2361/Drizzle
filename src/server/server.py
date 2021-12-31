import logging
import select
import socket
import sys
import threading

import msgpack

from exceptions import ExceptionCode, RequestException

logging.basicConfig(level=logging.DEBUG)
HEADER_TYPE_LEN = 1
HEADER_MSG_LEN = 7
IP = socket.gethostbyname(socket.gethostname())
PORT = 1234
FMT = "utf-8"

print(f"SERVER IP: {IP}")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((IP, PORT))
server_socket.listen()

sockets_list = [server_socket]
# uname -> addr: (IP, PORT)
clients: dict[str, tuple[str, int]] = {}


def receive_msg(client_socket: socket.socket) -> dict[str, str | bytes]:
    message_type = client_socket.recv(HEADER_TYPE_LEN).decode(FMT)
    if not len(message_type):
        raise RequestException(
            msg=f"Client at {client_socket.getpeername()} closed the connection",
            code=ExceptionCode.DISCONNECT,
        )
    elif message_type not in ("n", "r"):
        raise RequestException(
            msg="Invalid message type in header",
            code=ExceptionCode.INVALID_HEADER,
        )
    else:
        message_len = int(client_socket.recv(HEADER_MSG_LEN).decode(FMT))
        return {"type": message_type, "uname": client_socket.recv(message_len)}


def read_handler(notified_socket: socket.socket) -> None:
    global clients
    global sockets_list
    if notified_socket == server_socket:
        client_socket, client_addr = server_socket.accept()
        try:
            userdata = receive_msg(client_socket)
            if userdata["type"] == "n":
                sockets_list.append(client_socket)
                clients[userdata["uname"]] = client_addr
                logging.log(
                    level=logging.DEBUG,
                    msg=(
                        "Accepted new connection from"
                        f" {client_addr[0]}:{client_addr[1]}"
                        f" username: {userdata['uname'].decode(FMT)}"
                    ),
                )
            else:
                raise RequestException(
                    msg=f"Bad request from {client_addr}",
                    code=ExceptionCode.BAD_REQUEST,
                )
        except RequestException as e:
            if e.code != ExceptionCode.DISCONNECT:
                data: bytes = msgpack.packb(
                    e, default=RequestException.to_dict, use_bin_type=True
                )
                header = f"e{len(data):<{HEADER_MSG_LEN}}".encode(FMT)
                client_socket.send(header + data)
            logging.log(level=logging.ERROR, msg=f"Exception: {e.msg}")
            return
    else:
        try:
            request = receive_msg(notified_socket)
            if request["type"] == "r":
                response_data = clients.get(request["uname"])
                if response_data is not None:
                    logging.log(
                        level=logging.DEBUG,
                        msg=f"Valid request: {response_data}",
                    )
                    data: bytes = msgpack.packb(response_data)
                    header = f"r{len(data):<{HEADER_MSG_LEN}}".encode(FMT)
                    notified_socket.send(header + data)
                else:
                    raise RequestException(
                        msg=f"Username {request['uname'].decode(FMT)} not found",
                        code=ExceptionCode.NOT_FOUND,
                    )
            else:
                raise RequestException(
                    msg=f"Bad request from {notified_socket.getpeername()}",
                    code=ExceptionCode.BAD_REQUEST,
                )
        except TypeError as e:
            logging.log(level=logging.ERROR, msg=e)
            sys.exit(0)
        except RequestException as e:
            if e.code == ExceptionCode.DISCONNECT:
                try:
                    sockets_list.remove(notified_socket)
                    for uname, addr in clients.items():
                        if addr == notified_socket.getpeername():
                            del clients[uname]
                            break
                except ValueError:
                    logging.info("already removed")
            else:
                data: bytes = msgpack.packb(
                    e, default=RequestException.to_dict, use_bin_type=True
                )
                header = f"e{len(data):<{HEADER_MSG_LEN}}".encode(FMT)
                notified_socket.send(header + data)
            logging.log(level=logging.ERROR, msg=f"Exception: {e.msg}")
            return


while True:
    read_sockets: list[socket.socket]
    exception_sockets: list[socket.socket]

    read_sockets, _, exception_sockets = select.select(
        sockets_list, [], sockets_list
    )
    for notified_socket in read_sockets:
        # threads
        thread = threading.Thread(target=read_handler, args=(notified_socket,))
        thread.start()

    # for notified_socket in exception_sockets:
    #     sockets_list.remove(notified_socket)
    #     for uname, addr in clients.items():
    #         if addr == notified_socket.getpeername():
    #             del clients[uname]
    #             break
