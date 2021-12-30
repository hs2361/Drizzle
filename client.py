import logging
import socket

import msgpack

from exceptions import RequestException

logging.basicConfig(filename="./client.log", level=logging.DEBUG)

HEADER_TYPE_LEN = 1
HEADER_MSG_LEN = 7
IP = "127.0.0.1"
PORT = 1234
FMT = "utf-8"

my_username = input("Enter username: ")
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((IP, PORT))
# client_socket.setblocking(False)

username = my_username.encode(FMT)
username_header = f"n{len(username):<{HEADER_MSG_LEN}}".encode(FMT)
client_socket.send(username_header + username)

while True:
    recipient = input("Enter recipient's username: ")
    if recipient:
        recipient = recipient.encode(FMT)
        request_header = f"r{len(recipient):<{HEADER_MSG_LEN}}".encode(FMT)
        client_socket.send(request_header + recipient)
        res_type = client_socket.recv(HEADER_TYPE_LEN).decode(FMT)
        logging.log(level=logging.DEBUG, msg=f"Response type: {res_type}")
        response_length = int(
            client_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
        )
        response = client_socket.recv(response_length)
        if res_type == "r":
            # open new socket
            response = msgpack.unpackb(response, use_list=False)
            logging.log(level=logging.DEBUG, msg=f"Response: {response}")
        if res_type == "e":
            err: RequestException = msgpack.unpackb(
                response, object_hook=RequestException.from_dict, raw=False
            )
            logging.log(level=logging.ERROR, msg=err)
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
