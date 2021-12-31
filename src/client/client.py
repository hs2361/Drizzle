import logging
import select
import socket
import threading

import msgpack

from exceptions import RequestException

logging.basicConfig(level=logging.DEBUG)

HEADER_TYPE_LEN = 1
HEADER_MSG_LEN = 7
SERVER_IP = input("Enter SERVER IP: ")
SERVER_PORT = 1234
SERVER_ADDR = (SERVER_IP, SERVER_PORT)
FMT = "utf-8"
CLIENT_IP = socket.gethostbyname(socket.gethostname())
CLIENT_PORT = 4321

my_username = input("Enter username: ")
client_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_server_socket.connect((SERVER_IP, SERVER_PORT))
# client_socket.setblocking(False)

username = my_username.encode(FMT)
username_header = f"n{len(username):<{HEADER_MSG_LEN}}".encode(FMT)
client_server_socket.send(username_header + username)

receiving = False

connected = [client_server_socket]


def send_handler():
    while True:
        if not receiving:
            recipient = input("Enter recipient's username: ")
            if recipient:
                recipient = recipient.encode(FMT)
                request_header = f"r{len(recipient):<{HEADER_MSG_LEN}}".encode(
                    FMT
                )
                client_server_socket.send(request_header + recipient)
                res_type = client_server_socket.recv(HEADER_TYPE_LEN).decode(
                    FMT
                )
                logging.log(
                    level=logging.DEBUG, msg=f"Response type: {res_type}"
                )
                response_length = int(
                    client_server_socket.recv(HEADER_MSG_LEN)
                    .decode(FMT)
                    .strip()
                )
                response = client_server_socket.recv(response_length)
                if res_type == "r":
                    # open new socket
                    recipient_addr = msgpack.unpackb(response, use_list=False)
                    logging.log(
                        level=logging.DEBUG, msg=f"Response: {recipient_addr}"
                    )
                    # client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # client_server_socket.close()
                    client_server_socket.connect(recipient_addr)

                if res_type == "e":
                    err: RequestException = msgpack.unpackb(
                        response,
                        object_hook=RequestException.from_dict,
                        raw=False,
                    )
                    logging.log(level=logging.ERROR, msg=err)


def receive_handler():
    read_sockets, _, __ = select.select(connected, [], [])
    for notified_socket in read_sockets:
        if notified_socket is client_server_socket:
            peer_socket, peer_addr = client_server_socket.accept()
            client_server_socket.connect()
            connected.append(peer_socket)
        else:
            msg_len = int(
                notified_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
            )


send_thread = threading.Thread(target=send_handler)
receive_thread = threading.Thread(target=receive_handler)
send_thread.start()
receive_thread.start()


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
