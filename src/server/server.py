import logging
import select
import socket
import sys

import msgpack

from exceptions import ExceptionCode, RequestException

HEADER_TYPE_LEN = 1
HEADER_MSG_LEN = 7
IP = socket.gethostbyname(socket.gethostname())
PORT = 1234
FMT = "utf-8"

logging.basicConfig(
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler(f"/logs/server_{IP}.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

print(f"SERVER IP: {IP}")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((IP, PORT))
server_socket.listen(5)

sockets_list = [server_socket]
# uname -> addr: (IP, PORT)
clients: dict[str, str] = {}


def receive_msg(client_socket: socket.socket) -> dict[str, str | bytes]:
    message_type = client_socket.recv(HEADER_TYPE_LEN).decode(FMT)
    if not len(message_type):
        raise RequestException(
            msg=f"Client at {client_socket.getpeername()} closed the connection",
            code=ExceptionCode.DISCONNECT,
        )
    elif message_type not in ("n", "r", "l"):
        logging.error(f"Received message type {message_type}")
        raise RequestException(
            msg="Invalid message type in header",
            code=ExceptionCode.INVALID_HEADER,
        )
    else:
        message_len = int(client_socket.recv(HEADER_MSG_LEN).decode(FMT))
        query = client_socket.recv(message_len)
        logging.debug(
            f"Received packet: TYPE {message_type} QUERY {query} from {client_socket.getpeername()}"
        )
        return {"type": message_type, "query": query}


def read_handler(notified_socket: socket.socket) -> None:
    global clients
    global sockets_list
    if notified_socket == server_socket:
        client_socket, client_addr = server_socket.accept()
        try:
            userdata = receive_msg(client_socket)
            uname = userdata["query"].decode(FMT)
            sockets_list.append(client_socket)
            if userdata["type"] == "n":
                addr = clients.get(uname)
                logging.debug(
                    f"Registration request for username {uname} from address {client_addr}"
                )
                if addr is None:
                    clients[uname] = client_addr[0]
                    logging.log(
                        level=logging.DEBUG,
                        msg=(
                            "Accepted new connection from"
                            f" {client_addr[0]}:{client_addr[1]}"
                            f" username: {userdata['query'].decode(FMT)}"
                        ),
                    )
                    client_socket.send(b"n")
                else:
                    if addr != client_addr[0]:
                        raise RequestException(
                            msg=f"User with username {addr} already exists",
                            code=ExceptionCode.USER_EXISTS,
                        )
                    else:
                        raise RequestException(
                            msg="Cannot re-register user for same address",
                            code=ExceptionCode.BAD_REQUEST,
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
            for key, value in clients.items():
                if value == client_addr[0]:
                    del clients[key]
                    break
            else:
                logging.debug(f"Username for IP {client_addr[0]} not found")
            logging.log(level=logging.ERROR, msg=f"Exception: {e.msg}")
            return
    else:
        try:
            request = receive_msg(notified_socket)
            if request["type"] == "r":
                response_data = clients.get(request["query"].decode(FMT))
                if response_data is not None:
                    if response_data != notified_socket.getpeername()[0]:
                        logging.log(
                            level=logging.DEBUG,
                            msg=f"Valid request: {response_data}",
                        )
                        data: bytes = response_data.encode(FMT)
                        header = f"r{len(data):<{HEADER_MSG_LEN}}".encode(FMT)
                        notified_socket.send(header + data)
                    else:
                        raise RequestException(
                            msg="Cannot query for user having the same address",
                            code=ExceptionCode.BAD_REQUEST,
                        )
                else:
                    raise RequestException(
                        msg=f"Username {request['query'].decode(FMT)} not found",
                        code=ExceptionCode.NOT_FOUND,
                    )
            elif request["type"] == "l":
                lookup_addr = request["query"].decode(FMT)
                if lookup_addr != notified_socket.getpeername()[0]:
                    for key, value in clients.items():
                        if value == lookup_addr:
                            username = key.encode(FMT)
                            header = (
                                f"l{len(username):<{HEADER_MSG_LEN}}".encode(
                                    FMT
                                )
                            )
                            notified_socket.send(header + username)
                            break
                    else:
                        raise RequestException(
                            msg=f"Username for {lookup_addr} not found",
                            code=ExceptionCode.NOT_FOUND,
                        )
                else:
                    raise RequestException(
                        msg="Cannot query for user having the same address",
                        code=ExceptionCode.BAD_REQUEST,
                    )
            elif request["type"] == "n":
                uname = request["query"].decode(FMT)
                addr = clients.get(uname)
                client_addr = notified_socket.getpeername()
                logging.debug(
                    f"Registration request for username {uname} from address {client_addr}"
                )
                if addr is None:
                    clients[uname] = client_addr[0]
                    logging.log(
                        level=logging.DEBUG,
                        msg=(
                            "Accepted new connection from"
                            f" {client_addr[0]}:{client_addr[1]}"
                            f" username: {uname}"
                        ),
                    )
                    notified_socket.send(b"n")
                else:
                    if addr != client_addr[0]:
                        raise RequestException(
                            msg=f"User with username {addr} already exists",
                            code=ExceptionCode.USER_EXISTS,
                        )
                    else:
                        raise RequestException(
                            msg="Cannot re-register user for same address",
                            code=ExceptionCode.BAD_REQUEST,
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
                    addr = notified_socket.getpeername()[0]
                    for key, value in clients.items():
                        if value == addr:
                            del clients[key]
                            break
                    else:
                        logging.debug(f"Username for IP {addr} not found")
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
        # thread = threading.Thread(target=read_handler, args=(notified_socket,))
        # thread.run()
        read_handler(notified_socket)
