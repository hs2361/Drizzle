import logging
import select
import socket

import msgpack

from exceptions import ExceptionCode, RequestException

logging.basicConfig(level=logging.DEBUG)

HEADER_TYPE_LEN = 1
HEADER_MSG_LEN = 7
SERVER_IP = input("Enter SERVER IP: ")
SERVER_PORT = 1234
SERVER_ADDR = (SERVER_IP, SERVER_PORT)
FMT = "utf-8"
CLIENT_IP = socket.gethostbyname(socket.gethostname())
CLIENT_SEND_PORT = 5678
CLIENT_RECV_PORT = 4321

my_username = input("Enter username: ")
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
# client_socket.setblocking(False)

username = my_username.encode(FMT)
username_header = f"n{len(username):<{HEADER_MSG_LEN}}".encode(FMT)
client_send_socket.send(username_header + username)

receiving = False

connected = [client_recv_socket]


def send_handler():
    global client_send_socket
    # while True:
    # if not receiving:
    recipient = input("Enter recipient's username: ")
    if recipient:
        recipient = recipient.encode(FMT)
        request_header = f"r{len(recipient):<{HEADER_MSG_LEN}}".encode(FMT)
        logging.debug(f"Sent packet {(request_header + recipient).decode(FMT)}")
        client_send_socket.send(request_header + recipient)
        res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
        logging.log(level=logging.DEBUG, msg=f"Response type: {res_type}")
        response_length = int(
            client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
        )
        response = client_send_socket.recv(response_length)
        if res_type == "r":
            recipient_addr = msgpack.unpackb(response, use_list=False)
            logging.log(level=logging.DEBUG, msg=f"Response: {recipient_addr}")
            # client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_send_socket.close()
            client_send_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            # client_send_socket.bind((CLIENT_IP, CLIENT_SEND_PORT))
            client_send_socket.connect((recipient_addr[0], 4321))
            msg = "Test messsage".encode(FMT)
            header = f"m{len(msg):<{HEADER_MSG_LEN}}".encode(FMT)
            client_send_socket.send(header + msg)
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
    global username

    # while True:
    read_sockets, _, __ = select.select(connected, [], [])
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
                logging.debug(f"Sending packet {(header + lookup).decode(FMT)}")
                client_send_socket.send(header + lookup)
                res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
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
                        logging.info(
                            f"Username {username} is trying to send a message"
                        )
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
                return
        else:
            try:
                msg: str = receive_msg(notified_socket)
                logging.info(f"Received message {msg} from {username}")
            except RequestException as e:
                if e.code == ExceptionCode.DISCONNECT:
                    try:
                        connected.remove(notified_socket)
                    except ValueError:
                        logging.info("already removed")
                logging.log(level=logging.ERROR, msg=f"Exception: {e.msg}")
                return


# send_thread = threading.Thread(target=send_handler)
# receive_thread = threading.Thread(target=receive_handler)
# send_thread.start()
# receive_thread.start()

while True:
    send_handler()
    receive_handler()

# try:
#     while True:
#         # receive things
#         username_header = client_socket.recv(HEADER_MSG_LEN)
#         if not len(username_header):
#             print("Connection closed by server")
#             sys.exit()
#         username_len = int(username_header.decode(FMT).strip())
#         username = client_socket.recv(username_len)
#         request_header = client_socket.recv(HEADER_MSG_LEN)
#         message_length = int(request_header.decode(FMT).strip())
#         recipient = client_socket.recv(message_length).decode(FMT)
#         print(f"{username} > {recipient}")

# except IOError as e:
#     if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
#         print("Could not parse input: ", str(e))
#         sys.exit()
#     continue

# except Exception as e:
#     print("An error occured: ", str(e))
#     sys.exit()
