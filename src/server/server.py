import logging
import select
import socket
import sys
import time
from pathlib import Path

import msgpack
from tinydb import Query, TinyDB

sys.path.append("../")
from utils.constants import FMT, HEADER_MSG_LEN, HEADER_TYPE_LEN, SERVER_RECV_PORT
from utils.exceptions import ExceptionCode, RequestException
from utils.helpers import update_file_hash
from utils.socket_functions import get_ip, recvall
from utils.types import DBData, DirData, HeaderCode, SocketMessage, UpdateHashParams

IP = get_ip()


logging.basicConfig(
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler(f"{str(Path.home())}/.Drizzle/logs/server_{IP}.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

drizzle_db = TinyDB(f"{str(Path.home())}/.Drizzle/db/db.json")

print(f"SERVER IP: {IP}")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((IP, SERVER_RECV_PORT))
server_socket.listen(5)

sockets_list = [server_socket]
# uname -> IP
uname_to_ip: dict[str, str] = {}
ip_to_uname: dict[str, str] = {}


uname_to_status: dict[str, int] = {}


def receive_msg(client_socket: socket.socket) -> SocketMessage:
    message_type = client_socket.recv(HEADER_TYPE_LEN).decode(FMT)
    if not len(message_type):
        raise RequestException(
            msg=f"Client at {client_socket.getpeername()} closed the connection",
            code=ExceptionCode.DISCONNECT,
        )
    if message_type not in [
        HeaderCode.NEW_CONNECTION.value,
        HeaderCode.REQUEST_IP.value,
        HeaderCode.REQUEST_UNAME.value,
        HeaderCode.SHARE_DATA.value,
        HeaderCode.FILE_SEARCH.value,
        HeaderCode.UPDATE_HASH.value,
        HeaderCode.HEARTBEAT_REQUEST.value,
    ]:
        logging.error(msg=f"Received message type {message_type}")
        raise RequestException(
            msg=f"Invalid message type in header, received: {message_type}",
            code=ExceptionCode.INVALID_HEADER,
        )
    elif message_type == HeaderCode.HEARTBEAT_REQUEST.value:
        return {"type": HeaderCode(message_type), "query": "online"}
    else:
        message_len = int(client_socket.recv(HEADER_MSG_LEN).decode(FMT))
        query = recvall(client_socket, message_len)
        logging.debug(
            msg=f"Received packet: TYPE {message_type} LEN {message_len} from {client_socket.getpeername()}"
        )
        return {"type": HeaderCode(message_type), "query": query}


def read_handler(notified_socket: socket.socket) -> None:
    global uname_to_ip
    global sockets_list
    if notified_socket == server_socket:
        client_socket, client_addr = server_socket.accept()
        sockets_list.append(client_socket)
    else:
        try:
            request = receive_msg(notified_socket)
            client_addr = notified_socket.getpeername()
            if ip_to_uname.get(notified_socket.getpeername()[0]) is None:
                if request["type"] != HeaderCode.NEW_CONNECTION:
                    raise RequestException(
                        msg=f"User at {client_addr} not registered",
                        code=ExceptionCode.UNAUTHORIZED,
                    )
                uname = request["query"].decode(FMT)
                addr = uname_to_ip.get(uname)
                logging.debug(
                    msg=f"Registration request for username {uname} from address {client_addr}"
                )
                if addr is None:
                    uname_to_ip[uname] = client_addr[0]
                    ip_to_uname[client_addr[0]] = uname
                    logging.debug(
                        msg=(
                            "Accepted new connection from"
                            f" {client_addr[0]}:{client_addr[1]}"
                            f" username: {request['query'].decode(FMT)}"
                        )
                    )
                    notified_socket.send(f"{HeaderCode.NEW_CONNECTION.value}".encode(FMT))
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
                return
            match request["type"]:
                case HeaderCode.REQUEST_IP:
                    response_data = uname_to_ip.get(request["query"].decode(FMT))
                    if response_data is not None:
                        if response_data != notified_socket.getpeername()[0]:
                            logging.debug(msg=f"Valid request: {response_data}")
                            data = response_data.encode(FMT)
                            header = f"{HeaderCode.REQUEST_IP.value}{len(data):<{HEADER_MSG_LEN}}".encode(
                                FMT
                            )
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
                case HeaderCode.REQUEST_UNAME:
                    lookup_addr = request["query"].decode(FMT)
                    if lookup_addr != notified_socket.getpeername()[0]:
                        username = ip_to_uname.get(lookup_addr)
                        if username is not None:
                            username_bytes = username.encode(FMT)
                            header = f"{HeaderCode.REQUEST_UNAME.value}{len(username):<{HEADER_MSG_LEN}}".encode(
                                FMT
                            )
                            notified_socket.send(header + username_bytes)
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
                case HeaderCode.NEW_CONNECTION:
                    uname = request["query"].decode(FMT)
                    addr = uname_to_ip.get(uname)
                    client_addr = notified_socket.getpeername()
                    logging.debug(
                        f"Registration request for username {uname} from address {client_addr}"
                    )
                    if addr is None:
                        uname_to_ip[uname] = client_addr[0]
                        logging.debug(
                            msg=(
                                "Accepted new connection from"
                                f" {client_addr[0]}:{client_addr[1]}"
                                f" username: {uname}"
                            )
                        )
                        notified_socket.send(f"{HeaderCode.NEW_CONNECTION.value}".encode(FMT))
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
                case HeaderCode.SHARE_DATA:
                    share_data: list[DirData] = msgpack.unpackb(request["query"])
                    username = ip_to_uname.get(notified_socket.getpeername()[0])
                    User = Query()
                    logging.debug(f"Received update to share data for user {username}")
                    if username is not None:
                        drizzle_db.upsert(
                            {"uname": username, "share": share_data},
                            User.uname == username,
                        )
                    else:
                        raise RequestException(
                            msg=f"Username does not exist",
                            code=ExceptionCode.NOT_FOUND,
                        )
                case HeaderCode.UPDATE_HASH:
                    update_hash_params: UpdateHashParams = msgpack.unpackb(request["query"])
                    username = ip_to_uname.get(notified_socket.getpeername()[0])
                    if username is not None:
                        User = Query()
                        try:
                            user_share = drizzle_db.search(User.uname == username)[0]["share"]
                            update_file_hash(
                                user_share,
                                update_hash_params["filepath"],
                                update_hash_params["hash"],
                            )
                            drizzle_db.update({"share": user_share}, User.uname == username)
                        except IndexError:
                            raise RequestException(
                                msg=f"Username does not exist",
                                code=ExceptionCode.NOT_FOUND,
                            )
                    else:
                        raise RequestException(
                            msg=f"Username does not exist",
                            code=ExceptionCode.NOT_FOUND,
                        )
                case HeaderCode.FILE_SEARCH:
                    username = ip_to_uname.get(notified_socket.getpeername()[0])
                    user_exists = uname_to_ip.get(request["query"].decode(FMT), False)
                    # if username != request["query"] and user_exists:
                    if username is not None and user_exists:
                        User = Query()
                        browse_files: list[DBData] = drizzle_db.search(
                            User.uname == request["query"].decode(FMT)
                        )
                        print(browse_files)
                        browse_files_bytes = msgpack.packb(browse_files)
                        browse_files_header = f"{HeaderCode.FILE_SEARCH.value}{len(browse_files_bytes):<{HEADER_MSG_LEN}}".encode(
                            FMT
                        )
                        notified_socket.sendall(browse_files_header + browse_files_bytes)
                    else:
                        raise RequestException(
                            msg=f"User does not exist, {request['query'].decode(FMT)}",
                            code=ExceptionCode.NOT_FOUND,
                        )
                    # else:
                    #     raise RequestException(
                    #         msg=f"Cannot search for own files",
                    #         code=ExceptionCode.BAD_REQUEST,
                    #     )

                case HeaderCode.HEARTBEAT_REQUEST:
                    username = ip_to_uname.get(notified_socket.getpeername()[0])
                    if username is not None:
                        uname_to_status[username] = time.time()
                        data = msgpack.packb(uname_to_status)
                        header = f"{HeaderCode.HEARTBEAT_REQUEST.value}{len(data):<{HEADER_MSG_LEN}}".encode(
                            FMT
                        )
                        notified_socket.sendall(header + data)

                    else:
                        raise RequestException(
                            msg=f"Username does not exist",
                            code=ExceptionCode.NOT_FOUND,
                        )

                case _:
                    raise RequestException(
                        msg=f"Bad request from {notified_socket.getpeername()}",
                        code=ExceptionCode.BAD_REQUEST,
                    )
        except TypeError as e:
            logging.error(msg=e)
            # sys.exit(0)
        except RequestException as e:
            if e.code == ExceptionCode.DISCONNECT:
                try:
                    sockets_list.remove(notified_socket)
                    addr_to_remove: str = notified_socket.getpeername()[0]
                    uname = ip_to_uname.pop(addr_to_remove, None)
                    uname_to_ip.pop(uname, None)
                except ValueError:
                    logging.info("already removed")
            else:
                data = msgpack.packb(e, default=RequestException.to_dict, use_bin_type=True)
                header = f"{HeaderCode.ERROR.value}{len(data):<{HEADER_MSG_LEN}}".encode(FMT)
                notified_socket.send(header + data)
            logging.error(msg=f"Exception: {e.msg}")
            return


while True:
    read_sockets: list[socket.socket]
    exception_sockets: list[socket.socket]

    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list, 0.1)
    for notified_socket in read_sockets:
        read_handler(notified_socket)
