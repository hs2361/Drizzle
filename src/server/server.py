# Imports (standard libraries)
import logging
import select
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from pprint import pformat

# Imports (PyPI)
import msgpack
from tinydb import Query, TinyDB

# Imports (utilities)
from utils.constants import FMT, HEADER_MSG_LEN, HEADER_TYPE_LEN, SERVER_RECV_PORT
from utils.exceptions import ExceptionCode, RequestException
from utils.helpers import item_search, update_file_hash
from utils.socket_functions import get_self_ip, recvall
from utils.types import DBData, DirData, HeaderCode, ItemSearchResult, SocketMessage, UpdateHashParams

# Get the server IP
IP = get_self_ip()

app_dir = Path.home() / ".Drizzle"
app_dir.mkdir(exist_ok=True)
(app_dir / "logs").mkdir(exist_ok=True)
(app_dir / "db").mkdir(exist_ok=True)

# Logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler(
            f"{str(Path.home())}/.Drizzle/logs/server_{datetime.now().strftime('%d-%m-%Y_%H-%M-%S')}.log"
        ),
        logging.StreamHandler(sys.stdout),
    ],
)

# Load share database
drizzle_db = TinyDB(f"{str(Path.home())}/.Drizzle/db/db.json")

print(f"SERVER IP: {IP}")

# Socket to listen for incoming connections from peers
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Configuring the socket to reuse addresses and immediately transmit data
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

# Mark packets with TOS value of IPTOS_THROUGHPUT and IPTOS_LOWDELAY to optimize for throughput and low delay
server_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10 | 0x08)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 0x06)

# Bind the socket and make it listen for new connections from peers
server_socket.bind((IP, SERVER_RECV_PORT))
server_socket.listen(5)

# List of connected peers
sockets_list = [server_socket]
# To lookup IP of a given username
uname_to_ip: dict[str, str] = {}
# To lookup username of a given IP
ip_to_uname: dict[str, str] = {}
# Mapping from username to last seen timestamp
uname_to_status: dict[str, float] = {}


def receive_msg(client_socket: socket.socket) -> SocketMessage:
    """Receives incoming requests from peers

    Parameters
    ----------
    client_socket : socket.socket
        The socket on which to receive the message

    Returns
    ----------
    SocketMessage
        The type of the message and query received from the peer

    Raises
    ----------
    RequestException
        In case of any exceptions that occur in receiving the message
    """

    try:
        # Receive message type
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
            HeaderCode.FILE_BROWSE.value,
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
            # Update online status
            return {"type": HeaderCode(message_type), "query": "online"}
        else:
            # If any query is sent, update the last seen to the current time
            username = ip_to_uname.get(notified_socket.getpeername()[0])
            if username is not None:
                uname_to_status[username] = time.time()
            elif message_type != HeaderCode.NEW_CONNECTION.value:
                raise RequestException(
                    msg=f"Username does not exist",
                    code=ExceptionCode.NOT_FOUND,
                )

            # Receive the query and return it
            message_len = int(client_socket.recv(HEADER_MSG_LEN).decode(FMT))
            logging.debug(
                msg=f"Receiving packet: TYPE {message_type} LEN {message_len} from {client_socket.getpeername()}"
            )
            query = recvall(client_socket, message_len)
            return {"type": HeaderCode(message_type), "query": query}
    except Exception as e:
        logging.exception(f"Error receiving from peer: {e}")
        return {"type": HeaderCode.ERROR, "query": "Failed to receive"}


def read_handler(notified_socket: socket.socket) -> None:
    """Serves requests received from peers

    Parameters
    ----------
    notified_socket : socket.socket
        The socket on which to receive the request

    Raises
    ----------
    RequestException
        In case of any exceptions that occur in serving the request
    """

    global uname_to_ip
    global ip_to_uname
    global sockets_list

    # New connection
    if notified_socket == server_socket:
        # Accept the connection and add it to the list of connected peers
        client_socket, client_addr = server_socket.accept()
        sockets_list.append(client_socket)
    else:
        try:
            # Receive the message
            request = receive_msg(notified_socket)
            client_addr = notified_socket.getpeername()

            # Check if the request is from an unregistered user
            if ip_to_uname.get(notified_socket.getpeername()[0]) is None:
                if request["type"] != HeaderCode.NEW_CONNECTION:
                    raise RequestException(
                        msg=f"User at {client_addr} not registered",
                        code=ExceptionCode.UNAUTHORIZED,
                    )

                # First request from an unregistered user should be a registration request
                uname = request["query"].decode(FMT)
                addr = uname_to_ip.get(uname)
                logging.debug(msg=f"Registration request for username {uname} from address {client_addr}")

                # Store the IP of the user in the mapping
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
                    # Acknowledge successful registration
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

            # Requests from registered users
            match request["type"]:
                # Request the IP of a given username
                case HeaderCode.REQUEST_IP:
                    # Lookup the IP in the mapping
                    response_data = uname_to_ip.get(request["query"].decode(FMT))
                    if response_data is not None:
                        # If the user has not requested a lookup for their own IP
                        if response_data != notified_socket.getpeername()[0]:
                            logging.debug(msg=f"Valid request: {response_data}")
                            # Send the IP back to the user
                            ip_data = response_data.encode(FMT)
                            header = f"{HeaderCode.REQUEST_IP.value}{len(ip_data):<{HEADER_MSG_LEN}}".encode(FMT)
                            notified_socket.send(header + ip_data)
                        else:
                            raise RequestException(
                                msg="Cannot query for your own address",
                                code=ExceptionCode.BAD_REQUEST,
                            )
                    else:
                        raise RequestException(
                            msg=f"Username {request['query'].decode(FMT)} not found",
                            code=ExceptionCode.NOT_FOUND,
                        )
                # Request the username of a given IP
                case HeaderCode.REQUEST_UNAME:
                    lookup_addr = request["query"].decode(FMT)
                    # If the user has not requested a lookup for their own username
                    if lookup_addr != notified_socket.getpeername()[0]:
                        # Lookup the username in the mapping
                        username = ip_to_uname.get(lookup_addr)
                        if username is not None:
                            # Send the username back to the user
                            username_bytes = username.encode(FMT)
                            header = f"{HeaderCode.REQUEST_UNAME.value}{len(username):<{HEADER_MSG_LEN}}".encode(FMT)
                            notified_socket.send(header + username_bytes)
                        else:
                            raise RequestException(
                                msg=f"Username for {lookup_addr} not found",
                                code=ExceptionCode.NOT_FOUND,
                            )
                    else:
                        raise RequestException(
                            msg="Cannot query for your own username",
                            code=ExceptionCode.BAD_REQUEST,
                        )
                # Registration request for a new user
                case HeaderCode.NEW_CONNECTION:
                    uname = request["query"].decode(FMT)
                    # Check if the user is already registered
                    addr = uname_to_ip.get(uname)
                    client_addr = notified_socket.getpeername()
                    logging.debug(f"Registration request for username {uname} from address {client_addr}")
                    if addr is None:
                        # Store the user's IP in the mapping
                        uname_to_ip[uname] = client_addr[0]
                        logging.debug(
                            msg=(
                                "Accepted new connection from"
                                f" {client_addr[0]}:{client_addr[1]}"
                                f" username: {uname}"
                            )
                        )
                        # Acknowledge successful registration
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
                # Sending share data of a user
                case HeaderCode.SHARE_DATA:
                    share_data: list[DirData] = msgpack.unpackb(request["query"])
                    # Check if the user is registered
                    username = ip_to_uname.get(notified_socket.getpeername()[0])
                    User = Query()
                    logging.debug(f"Received update to share data for user {username}")
                    if username is not None:
                        # Update the share data under the username key in the database if it exists
                        # or insert it if it does not exists
                        drizzle_db.upsert(
                            {"uname": username, "share": share_data},
                            User.uname == username,
                        )
                        # Acknowledge successfully adding share data
                        notified_socket.send(HeaderCode.SHARE_DATA.value.encode(FMT))
                    else:
                        raise RequestException(
                            msg=f"Username does not exist",
                            code=ExceptionCode.NOT_FOUND,
                        )
                # Updating hash of a file item
                case HeaderCode.UPDATE_HASH:
                    update_hash_params: UpdateHashParams = msgpack.unpackb(request["query"])
                    # Check if the user is registered
                    username = ip_to_uname.get(notified_socket.getpeername()[0])
                    if username is not None:
                        User = Query()
                        try:
                            # Search for the user's files
                            user_share = drizzle_db.search(User.uname == username)[0]["share"]
                            # Update the file item with the given hash
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
                # Browse the share data of a user
                case HeaderCode.FILE_BROWSE:
                    # Check if the user is registered and if the queried username exists
                    username = ip_to_uname.get(notified_socket.getpeername()[0])
                    user_exists = uname_to_ip.get(request["query"].decode(FMT), False)
                    if username is not None and user_exists:
                        User = Query()
                        # Search for the queried user's files
                        browse_files: list[DBData] = drizzle_db.search(User.uname == request["query"].decode(FMT))
                        # Send results back to the user
                        search_result_bytes = msgpack.packb(browse_files)
                        search_result_header = (
                            f"{HeaderCode.FILE_BROWSE.value}{len(search_result_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
                        )
                        notified_socket.sendall(search_result_header + search_result_bytes)
                    else:
                        raise RequestException(
                            msg=f"User does not exist, {request['query'].decode(FMT)}",
                            code=ExceptionCode.NOT_FOUND,
                        )
                # Search for a file across share data of all users
                case HeaderCode.FILE_SEARCH:
                    # Check if the user is registered
                    username = ip_to_uname.get(notified_socket.getpeername()[0])
                    search_query = request["query"].decode(FMT).strip()
                    if username is not None and search_query:
                        data: list[DBData] = drizzle_db.all()
                        result: list[ItemSearchResult] = []
                        # Loop through all the users
                        for user in data:
                            # Skip the user's own files
                            if user["uname"] == username:
                                continue
                            # Search through the user's share data
                            dir: list[DirData] = user["share"]
                            item_search(dir, result, search_query.lower(), user["uname"])
                        logging.debug(f"{pformat(result)}")

                        # Send search results back to the user
                        search_result_bytes = msgpack.packb(result)
                        search_result_header = (
                            f"{HeaderCode.FILE_SEARCH.value}{len(search_result_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
                        )

                        notified_socket.sendall(search_result_header + search_result_bytes)
                    else:
                        raise RequestException(
                            msg=f"User does not exist",
                            code=ExceptionCode.NOT_FOUND,
                        )
                # Update to user's online status
                case HeaderCode.HEARTBEAT_REQUEST:
                    # Check if the user is registered
                    username = ip_to_uname.get(notified_socket.getpeername()[0])
                    if username is not None:
                        # Update the user's last seen to the current time
                        uname_to_status[username] = time.time()
                        # Return the last seen status of all users except the current user
                        filtered_status = {k: v for k, v in uname_to_status.items() if k != username}
                        status_data = msgpack.packb(filtered_status)
                        header = f"{HeaderCode.HEARTBEAT_REQUEST.value}{len(status_data):<{HEADER_MSG_LEN}}".encode(FMT)
                        notified_socket.sendall(header + status_data)
                    else:
                        raise RequestException(
                            msg=f"Username does not exist",
                            code=ExceptionCode.NOT_FOUND,
                        )
                # Client sent an error
                case HeaderCode.ERROR:
                    raise RequestException(
                        msg=f"{request['query']}",
                        code=ExceptionCode.DISCONNECT,
                    )
                # Bad requests with invalid header
                case _:
                    raise RequestException(
                        msg=f"Bad request from {notified_socket.getpeername()}",
                        code=ExceptionCode.BAD_REQUEST,
                    )
        except TypeError as e:
            logging.exception(msg=e)
        # Broken pipe or other OS errors
        except OSError:
            try:
                # Remove the socket from the list of connected sockets
                sockets_list.remove(notified_socket)
                # Remove the user from the lookup mappings
                addr_to_remove = notified_socket.getpeername()[0]
                uname = ip_to_uname.pop(addr_to_remove, None)
                uname_to_ip.pop(uname, None)
            except ValueError:
                logging.info("already removed")
            except Exception as e:
                logging.exception(f"Error while removing socket: {e}")
        # Returning raised errors back to the user
        except RequestException as e:
            if e.code == ExceptionCode.DISCONNECT:
                try:
                    # Remove the socket from the list of connected sockets
                    sockets_list.remove(notified_socket)
                    addr_to_remove = notified_socket.getpeername()[0]
                    uname = ip_to_uname.pop(addr_to_remove, None)
                    uname_to_ip.pop(uname, None)
                except ValueError:
                    logging.info("already removed")
            else:
                # Encode and send the error back to the user
                exc_data = msgpack.packb(e, default=RequestException.to_dict, use_bin_type=True)
                header = f"{HeaderCode.ERROR.value}{len(exc_data):<{HEADER_MSG_LEN}}".encode(FMT)
                notified_socket.send(header + exc_data)
            logging.exception(msg=f"Exception: {e.msg}")
            return
        except Exception as e:
            logging.exception(e)


while True:
    read_sockets: list[socket.socket]
    exception_sockets: list[socket.socket]

    # Use the select() system call to get a list of sockets which are ready to read
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list, 0.1)
    for notified_socket in read_sockets:
        read_handler(notified_socket)
