import logging
import select
import socket
import sqlite3
import sys

import msgpack

from utils.exceptions import ExceptionCode, RequestException
from utils.types import FileMetadata, FileSearchResult, HeaderCode, Message

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
# uname -> IP
uname_to_ip: dict[str, str] = {}
ip_to_uname: dict[str, str] = {}

db_connection = sqlite3.connect("files.db")
db = db_connection.cursor()
db.execute(
    """
    CREATE TABLE IF NOT EXISTS files (
        uname TEXT,
        filepath TEXT,
        filesize INTEGER,
        hash TEXT,
        PRIMARY KEY (uname, filepath)
    )
    """
)
db.execute(
    """
    CREATE INDEX IF NOT EXISTS files_by_filepath ON files(filepath)
    """
)
db_connection.commit()


# NEW SHARE_DATA
def insert_share_data(uname: str, filepath: str, filesize: int, hash: str):
    query = """
            INSERT INTO files(uname, filepath, filesize, hash) VALUES (?, ?, ?, ?)
            """
    args = (uname, filepath, filesize, hash)
    db.execute(query, args)


def search_files(query_string: str, self_uname: str) -> list[FileSearchResult]:
    query = """
            SELECT uname, filepath, filesize, hash FROM files WHERE filepath LIKE ? AND uname != ?
            """
    args = ("%" + query_string + "%", self_uname)
    db.execute(query, args)
    return [FileSearchResult(*result) for result in db.fetchall()]


# UPDATE SHARE_DATA
"""
DELETE FROM files WHERE uname = {uname} AND filepath={filepath}
"""


def receive_msg(client_socket: socket.socket) -> Message:
    message_type = client_socket.recv(HEADER_TYPE_LEN).decode(FMT)
    if not len(message_type):
        raise RequestException(
            msg=f"Client at {client_socket.getpeername()} closed the connection",
            code=ExceptionCode.DISCONNECT,
        )
    if message_type not in [
        HeaderCode.NEW_CONNECTION.value,
        HeaderCode.REQUEST_UNAME.value,
        HeaderCode.LOOKUP_ADDRESS.value,
        HeaderCode.SHARE_DATA.value,
        HeaderCode.FILE_SEARCH.value,
    ]:
        logging.error(msg=f"Received message type {message_type}")
        raise RequestException(
            msg="Invalid message type in header",
            code=ExceptionCode.INVALID_HEADER,
        )
    else:
        message_len = int(client_socket.recv(HEADER_MSG_LEN).decode(FMT))
        query = client_socket.recv(message_len)
        logging.debug(
            msg=f"Received packet: TYPE {message_type} QUERY {query!r} from {client_socket.getpeername()}"
        )
        return {"type": HeaderCode(message_type), "query": query}


def read_handler(notified_socket: socket.socket) -> None:
    global uname_to_ip
    global sockets_list
    if notified_socket == server_socket:
        client_socket, client_addr = server_socket.accept()
        try:
            userdata = receive_msg(client_socket)
            uname = userdata["query"].decode(FMT)
            sockets_list.append(client_socket)
            if userdata["type"] == HeaderCode.NEW_CONNECTION:
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
                            f" username: {userdata['query'].decode(FMT)}"
                        )
                    )
                    client_socket.send(f"{HeaderCode.NEW_CONNECTION.value}".encode(FMT))
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
                data: bytes = msgpack.packb(e, default=RequestException.to_dict, use_bin_type=True)
                header = f"{HeaderCode.ERROR.value}{len(data):<{HEADER_MSG_LEN}}".encode(FMT)
                client_socket.send(header + data)
            uname = ip_to_uname.pop(client_addr[0], None)
            uname_to_ip.pop(uname, None)
            logging.error(msg=e.msg)
            return
    else:
        try:
            request = receive_msg(notified_socket)
            if request["type"] == HeaderCode.REQUEST_UNAME:
                response_data = uname_to_ip.get(request["query"].decode(FMT))
                if response_data is not None:
                    if response_data != notified_socket.getpeername()[0]:
                        logging.debug(msg=f"Valid request: {response_data}")
                        data = response_data.encode(FMT)
                        header = (
                            f"{HeaderCode.REQUEST_UNAME.value}{len(data):<{HEADER_MSG_LEN}}".encode(
                                FMT
                            )
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
            elif request["type"] == HeaderCode.LOOKUP_ADDRESS:
                lookup_addr = request["query"].decode(FMT)
                if lookup_addr != notified_socket.getpeername()[0]:
                    username = ip_to_uname.get(lookup_addr)
                    if username is not None:
                        username_bytes = username.encode(FMT)
                        header = f"{HeaderCode.LOOKUP_ADDRESS.value}{len(username):<{HEADER_MSG_LEN}}".encode(
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
            elif request["type"] == HeaderCode.NEW_CONNECTION:
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
            elif request["type"] == HeaderCode.SHARE_DATA:
                share_data: list[FileMetadata] = msgpack.unpackb(request["query"])
                username = ip_to_uname.get(notified_socket.getpeername()[0])
                if username is not None:
                    for file_data in share_data:
                        insert_share_data(
                            username, file_data["name"], file_data["size"], file_data["hash"]
                        )
                    db_connection.commit()
                else:
                    raise RequestException(
                        msg=f"Username does not exist",
                        code=ExceptionCode.NOT_FOUND,
                    )
            elif request["type"] == HeaderCode.FILE_SEARCH:
                username = ip_to_uname.get(notified_socket.getpeername()[0])
                if username is not None:
                    search_result = search_files(request["query"].decode(FMT), username)
                    logging.debug(f"{search_result}")
                    search_result_bytes = msgpack.packb(search_result)
                    search_result_header = f"{HeaderCode.FILE_SEARCH.value}{len(search_result_bytes):<{HEADER_MSG_LEN}}".encode(
                        FMT
                    )
                    notified_socket.send(search_result_header + search_result_bytes)
                else:
                    raise RequestException(
                        msg=f"Username does not exist",
                        code=ExceptionCode.NOT_FOUND,
                    )
            else:
                raise RequestException(
                    msg=f"Bad request from {notified_socket.getpeername()}",
                    code=ExceptionCode.BAD_REQUEST,
                )
        except TypeError as e:
            logging.error(msg=e)
            sys.exit(0)
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

    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
    for notified_socket in read_sockets:
        read_handler(notified_socket)
