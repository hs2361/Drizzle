import select
import socket
import threading

import msgpack

HEADER_TYPE_LEN = 1
HEADER_MSG_LEN = 7
IP = "127.0.0.1"
PORT = 1234
FMT = "utf-8"

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((IP, PORT))
server_socket.listen()

sockets_list = [server_socket]
# uname -> addr: (IP, PORT)
clients: dict[str, socket._RetAddress] = {}


def receive_msg(client_socket: socket.socket) -> dict[str, str | bytes]:
    message_type = client_socket.recv(HEADER_TYPE_LEN).decode(FMT)
    if not len(message_type):
        raise Exception(msg="Client closed the connection")
    elif message_type not in ("n", "r"):
        raise Exception(msg="Invalid message type in header")
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
                print(
                    (
                        "Accepted new connection from"
                        f" {client_addr[0]}:{client_addr[1]}"
                        f" username: {userdata['uname'].decode(FMT)}"
                    )
                )
            else:
                print(f"Bad request from {client_addr}")
                return
        except Exception as e:
            print(f"Exception: {e.msg}")
            return
    else:

        try:
            request = receive_msg(notified_socket)
            if request["type"] == "r":
                response_data = clients.get(request["uname"])
                if response_data is not None:
                    data: bytes = msgpack.packb(response_data)
                    notified_socket.send(data)
                else:
                    print(f"Username {request['uname']} not found")
                    return
            else:
                print(f"Bad request from {notified_socket.getpeername()}")
                return
        except Exception as e:
            sockets_list.remove(notified_socket)
            for uname, addr in clients.items():
                if addr == notified_socket.getpeername():
                    del clients[uname]
                    break
            print(f"Exception: {e.msg}")
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

    for notified_socket in exception_sockets:
        sockets_list.remove(notified_socket)
        for uname, addr in clients.items():
            if addr == notified_socket.getpeername():
                del clients[uname]
                break
