import logging
import socket
from pathlib import Path

import msgpack

from utils.constants import FMT, HEADER_MSG_LEN, HEADER_TYPE_LEN
from utils.exceptions import RequestException
from utils.helpers import path_to_dict
from utils.types import HeaderCode


def get_self_ip() -> str:
    """Utility to obtain the current user's own IP address.

    Starts a connection with a temporary socket and attempts to find its own IP.

    Returns
    -------
    str
        IP address of this client
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(("1.1.1.1", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def request_uname(ip: str, client_send_socket: socket.socket) -> str | None:
    """Utililty that requests the server for a peer's username against a known IP address.

    Parameters
    ----------
    ip : str
        (Known) IP address of a peer.
    client_send_socket : socket.socket
        Socket object that is connected to the server.

    Returns
    -------
    str | None
        Returns the username of peer if given by the server, or returns None if not found.
    """
    ip_bytes = ip.encode(FMT)
    request_header = f"{HeaderCode.REQUEST_UNAME.value}{len(ip_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
    logging.debug(msg=f"Sent packet {(request_header + ip_bytes).decode(FMT)}")
    client_send_socket.send(request_header + ip_bytes)
    res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
    logging.debug(msg=f"Response type: {res_type}")
    response_length = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
    peer_ip_bytes = client_send_socket.recv(response_length)
    if res_type == HeaderCode.REQUEST_UNAME.value:
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


def request_ip(uname: str, client_send_socket: socket.socket) -> str | None:
    """Utililty that requests the server for a peer's IP against a known username.

    Parameters
    ----------
    uname : str
        (Known) username of a peer.
    client_send_socket : socket.socket
        Socket object that is connected to the server.

    Returns
    -------
    str | None
        Returns the IP address of peer if given by the server, or returns None if not found.

    Raises
    ------
    Exception
        Exception raised if communication with server fails
    """
    uname_bytes = uname.encode(FMT)
    request_header = f"{HeaderCode.REQUEST_IP.value}{len(uname_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
    try:
        client_send_socket.send(request_header + uname_bytes)
        logging.debug(msg=f"Sent packet {(request_header + uname_bytes).decode(FMT)}")
        res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
        logging.debug(msg=f"Response type: {res_type}")
        response_length = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
        res_bytes = client_send_socket.recv(response_length)
        logging.debug(msg=f"peer ip response {res_bytes!r}")
        if res_type == HeaderCode.REQUEST_IP.value:
            return res_bytes.decode(FMT)
        elif res_type == HeaderCode.ERROR.value:
            error: RequestException = msgpack.unpackb(
                res_bytes,
                object_hook=RequestException.from_dict,
                raw=False,
            )
            logging.error(msg=error.msg)
            return None
        else:
            logging.error(f"Invalid message type in header: {res_type}")
            return None
    except Exception as e:
        logging.exception(e)
        return None


def recvall(peer_socket: socket.socket, length: int) -> bytes:
    """Utility to ensure lossless reception of data for a large communication.

    The function receives in a loop till the expected amount of data is received.
    This is done prevent data loss, as the socket.recv method by itself cannot guarantee a lossless reception.

    Parameters
    ----------
    peer_socket : socket.socket
        Socket on which to receive data.
    length : int
        Expected size of incoming data.

    Returns
    -------
    bytes
        Returns all the data received by the function.
    """
    received = 0
    data: bytes = b""
    while received != length:
        new_data = peer_socket.recv(length)
        if not len(new_data):
            break
        data += new_data
        received += len(new_data)
    return data


def update_share_data(share_folder_path: Path, client_send_socket: socket.socket):
    """Utility to send new share folder data to the server.

    Generates dictionary representation of the share folder and sends it to the server.

    Parameters
    ----------
    share_folder_path : Path
        Path to user's share folder.
    client_send_socket : socket.socket
        Socket object that is connected to the server.
    """
    share_data = msgpack.packb(path_to_dict(share_folder_path, str(share_folder_path))["children"])
    share_data_header = f"{HeaderCode.SHARE_DATA.value}{len(share_data):<{HEADER_MSG_LEN}}".encode(FMT)
    client_send_socket.sendall(share_data_header + share_data)
    msg_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
    if msg_type != HeaderCode.SHARE_DATA.value:
        logging.error("Invalid message type from server")
