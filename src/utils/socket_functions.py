import logging
import socket

import msgpack

from utils.constants import FMT, HEADER_MSG_LEN, HEADER_TYPE_LEN
from utils.exceptions import RequestException
from utils.types import HeaderCode


def request_ip(uname: str, client_send_socket: socket.socket) -> str | None:
    uname_bytes = uname.encode(FMT)
    request_header = f"{HeaderCode.REQUEST_IP.value}{len(uname_bytes):<{HEADER_MSG_LEN}}".encode(
        FMT
    )
    logging.debug(msg=f"Sent packet {(request_header + uname_bytes).decode(FMT)}")
    client_send_socket.send(request_header + uname_bytes)
    res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
    logging.debug(msg=f"Response type: {res_type}")
    response_length = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
    peer_ip_bytes = client_send_socket.recv(response_length)
    if res_type == HeaderCode.REQUEST_IP.value:
        return peer_ip_bytes.decode(FMT)
    elif res_type == HeaderCode.ERROR.value:
        res_len = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
        res = client_send_socket.recv(res_len)
        error: RequestException = msgpack.unpackb(
            res,
            object_hook=RequestException.from_dict,
            raw=False,
        )
        logging.error(msg=error)
        return None
    else:
        logging.error(f"Invalid message type in header: {res_type}")
        return None


def recvall(peer_socket: socket.socket, length: int) -> bytes:
    received = 0
    data: bytes = b""
    while received != length:
        new_data = peer_socket.recv(length)
        if not len(new_data):
            break
        data += new_data
        received += len(new_data)
    # if received != length:
    #     raise RequestException(msg="Data received is incomplete", code=ExceptionCode.INCOMPLETE)
    return data
