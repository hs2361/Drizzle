import hashlib
import json
import logging
import select
import shutil
import socket
import sys
import time
from pathlib import Path

import msgpack
from PyQt5.QtCore import *
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import *
from ui.ErrorDialog import Ui_ErrorDialog
from ui.FileInfoDialog import Ui_FileInfoDialog
from ui.FileProgressWidget import Ui_FileProgressWidget
from ui.SettingsDialog import Ui_SettingsDialog

sys.path.append("../")
from utils.constants import (
    CLIENT_RECV_PORT,
    CLIENT_SEND_PORT,
    FILE_BUFFER_LEN,
    FMT,
    HEADER_MSG_LEN,
    HEADER_TYPE_LEN,
    HEARTBEAT_TIMER,
    LEADING_HTML,
    ONLINE_TIMEOUT,
    SERVER_RECV_PORT,
    TEMP_FOLDER_PATH,
    TRAILING_HTML,
)
from utils.exceptions import ExceptionCode, RequestException
from utils.helpers import (
    convert_size,
    get_directory_size,
    get_file_hash,
    get_files_in_dir,
    get_unique_filename,
    import_file_to_share,
    path_to_dict,
)
from utils.socket_functions import (
    get_self_ip,
    recvall,
    request_ip,
    request_uname,
    update_share_data,
)
from utils.types import (
    DBData,
    DirData,
    DirProgress,
    FileMetadata,
    FileRequest,
    HeaderCode,
    Message,
    TransferProgress,
    TransferStatus,
    UpdateHashParams,
    UserSettings,
)

SERVER_IP = ""
SERVER_ADDR = ()
CLIENT_IP = get_self_ip()

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler(f"{str(Path.home())}/.Drizzle/logs/client.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

client_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # to connect to main server
client_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # to receive new connections
client_send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
client_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
client_send_socket.bind((CLIENT_IP, CLIENT_SEND_PORT))
client_recv_socket.bind((CLIENT_IP, CLIENT_RECV_PORT))
client_recv_socket.listen(5)

connected = [client_recv_socket]
uname_to_status: dict[str, int] = {}
messages_store: dict[str, list[Message]] = {}
selected_uname: str = ""
selected_file_items: list[DirData] = []
self_uname: str = ""
transfer_progress: dict[Path, TransferProgress] = {}
progress_widgets: dict[Path, Ui_FileProgressWidget] = {}
dir_progress: dict[Path, DirProgress] = {}
user_settings: UserSettings = {}
uname_to_ip: dict[str, str] = {}
ip_to_uname: dict[str, str] = {}


class ServerMutex(QMutex):
    def __init__(self) -> None:
        super().__init__()

    def lock(self, caller: str) -> None:
        logging.debug(msg=f"Mutex locked by {caller}")
        return super().lock()

    def unlock(self, caller: str) -> None:
        logging.debug(msg=f"Mutex unlocked by {caller}")
        return super().unlock()


server_socket_mutex = ServerMutex()


class HeartbeatWorker(QObject):
    update_status = pyqtSignal(dict)

    def __init__(self, settings: UserSettings):
        super(HeartbeatWorker, self).__init__()
        self.settings = settings

    def run(self):
        global client_send_socket
        global server_socket_mutex
        heartbeat = HeaderCode.HEARTBEAT_REQUEST.value.encode(FMT)
        while True:
            time.sleep(HEARTBEAT_TIMER)
            server_socket_mutex.lock("heartbeat worker")
            client_send_socket.send(heartbeat)
            type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
            if type == HeaderCode.HEARTBEAT_REQUEST.value:
                length = int(client_send_socket.recv((HEADER_MSG_LEN)).decode(FMT))
                new_status = msgpack.unpackb(client_send_socket.recv(length))
                server_socket_mutex.unlock("heartbeat worker")
                self.update_status.emit(new_status)
            else:
                server_socket_mutex.unlock("heartbeat worker")
                logging.error(
                    f"Server sent invalid message type in header: {type}",
                )
                error_dialog = QDialog()
                error_dialog.ui = Ui_ErrorDialog(
                    error_dialog, f"Cannot establish connection with server", self.settings
                )
                sys.exit(error_dialog.exec())


class HandleFileRequestWorker(QRunnable):
    def __init__(
        self, filepath: Path, requester: tuple[str, int], request_hash: bool, resume_offset: int
    ):
        super().__init__()
        self.filepath = filepath
        self.requester = requester
        self.request_hash = request_hash
        self.resume_offset = resume_offset

    def run(self) -> None:
        file_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        file_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        file_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
        file_send_socket.connect(self.requester)
        hash = ""
        # compression = CompressionMethod.NONE

        # file_size = filepath.stat().st_size
        # if file_size < COMPRESSION_THRESHOLD:
        #     compression = CompressionMethod.ZSTD
        #     compressor = zstd.ZstdCompressor()
        #     with filepath.open(mode="rb") as uncompressed_file:
        #         with compressor.stream_writer(uncompressed_file) as writer:
        #             pass
        if self.request_hash:
            hash = get_file_hash(str(self.filepath))

        filemetadata: FileMetadata = {
            "path": str(self.filepath).removeprefix(user_settings["share_folder_path"] + "/"),
            "size": self.filepath.stat().st_size,
            "hash": hash if self.request_hash else None,
            # "compression": compression,
        }

        logging.debug(filemetadata)
        filemetadata_bytes = msgpack.packb(filemetadata)
        # logging.debug(filemetadata_bytes)
        filesend_header = (
            f"{HeaderCode.FILE.value}{len(filemetadata_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
        )

        try:
            file_to_send = self.filepath.open(mode="rb")
            logging.debug(f"Sending file {filemetadata['path']} to {self.requester}")
            file_send_socket.send(filesend_header + filemetadata_bytes)

            total_bytes_read = 0
            file_to_send.seek(self.resume_offset)
            while total_bytes_read != filemetadata["size"] - self.resume_offset:
                bytes_read = file_to_send.read(FILE_BUFFER_LEN)
                num_bytes = file_send_socket.send(bytes_read)
                total_bytes_read += num_bytes
                print("\nFile Sent")
            file_to_send.close()
            file_send_socket.close()
            if self.request_hash:
                update_hash_params: UpdateHashParams = {
                    "filepath": str(self.filepath).removeprefix(
                        user_settings["share_folder_path"] + "/"
                    ),
                    "hash": hash,
                }
                update_hash_bytes = msgpack.packb(update_hash_params)
                update_hash_header = f"{HeaderCode.UPDATE_HASH.value}{len(update_hash_bytes):<{HEADER_MSG_LEN}}".encode(
                    FMT
                )
                server_socket_mutex.lock("handle file request worker")
                client_send_socket.send(update_hash_header + update_hash_bytes)
                server_socket_mutex.unlock("handle file request worker")
        except Exception as e:
            logging.error(f"File Sending failed: {e}", exc_info=True)


class ReceiveHandler(QObject):
    message_received = pyqtSignal(dict)
    file_received = pyqtSignal(dict)

    def receive_msg(self, socket: socket.socket) -> str:
        global client_send_socket
        global user_settings
        logging.debug(f"Receiving from {socket.getpeername()}")
        message_type = socket.recv(HEADER_TYPE_LEN).decode(FMT)
        if not len(message_type):
            raise RequestException(
                msg=f"Peer at {socket.getpeername()} closed the connection",
                code=ExceptionCode.DISCONNECT,
            )
        elif message_type not in [
            HeaderCode.MESSAGE.value,
            HeaderCode.FILE.value,
            HeaderCode.FILE_REQUEST.value,
        ]:
            raise RequestException(
                msg=f"Invalid message type in header. Received [{message_type}]",
                code=ExceptionCode.INVALID_HEADER,
            )
        else:
            match message_type:
                case HeaderCode.FILE.value:
                    file_header_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                    file_header: FileMetadata = msgpack.unpackb(socket.recv(file_header_len))
                    logging.debug(msg=f"receiving file with metadata {file_header}")
                    write_path: Path = get_unique_filename(
                        Path(user_settings["downloads_folder_path"]) / file_header["path"],
                        Path(user_settings["downloads_folder_path"]),
                    )
                    try:
                        file_to_write = open(str(write_path), "wb")
                        logging.debug(f"Creating and writing to {write_path}")
                        try:
                            byte_count = 0

                            while byte_count != file_header["size"]:
                                file_bytes_read: bytes = socket.recv(FILE_BUFFER_LEN)
                                byte_count += len(file_bytes_read)
                                file_to_write.write(file_bytes_read)
                            file_to_write.close()
                            return f"Received file {write_path.name}"
                        except Exception as e:
                            logging.error(e)
                            return "File received but failed to save"
                    except Exception as e:
                        logging.error(e)
                        return "Unable to write file"
                case HeaderCode.FILE_REQUEST.value:
                    req_header_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                    file_req_header: FileRequest = msgpack.unpackb(socket.recv(req_header_len))
                    logging.debug(msg=f"Received request: {file_req_header}")
                    requested_file_path = (
                        Path(user_settings["share_folder_path"]) / file_req_header["filepath"]
                    )
                    if requested_file_path.is_file():
                        socket.send(HeaderCode.FILE_REQUEST.value.encode(FMT))
                        # send_file_thread = threading.Thread(
                        #     target=self.send_file,
                        #     args=(
                        #         requested_file_path,
                        #         (socket.getpeername()[0], file_req_header["port"]),
                        #         file_req_header["request_hash"],
                        #         file_req_header["resume_offset"],
                        #     ),
                        # )
                        send_file_handler = HandleFileRequestWorker(
                            requested_file_path,
                            (socket.getpeername()[0], file_req_header["port"]),
                            file_req_header["request_hash"],
                            file_req_header["resume_offset"],
                        )
                        send_file_pool = QThreadPool.globalInstance()
                        send_file_pool.setMaxThreadCount(4)
                        send_file_pool.start(send_file_handler)
                        return "File requested by user"
                    elif requested_file_path.is_dir():
                        raise RequestException(
                            f"Requested a directory, {file_req_header['filepath']} is not a file.",
                            ExceptionCode.BAD_REQUEST,
                        )
                    else:
                        share_data = msgpack.packb(
                            path_to_dict(
                                Path(user_settings["share_folder_path"]),
                                user_settings["share_folder_path"],
                            )["children"]
                        )
                        share_data_header = f"{HeaderCode.SHARE_DATA.value}{len(share_data):<{HEADER_MSG_LEN}}".encode(
                            FMT
                        )
                        server_socket_mutex.lock("receive handler share data")
                        client_send_socket.sendall(share_data_header + share_data)
                        server_socket_mutex.unlock("receive handler share data")
                        raise RequestException(
                            f"Requested file {file_req_header['filepath']} is not available",
                            ExceptionCode.NOT_FOUND,
                        )
                case _:
                    message_len = int(socket.recv(HEADER_MSG_LEN).decode(FMT))
                    return recvall(socket, message_len).decode(FMT)

    def run(self):
        global message_store
        global client_send_socket
        global client_recv_socket
        global connected
        global server_socket_mutex

        # peers: dict[str, str] = {}

        while True:
            read_sockets: list[socket.socket]
            read_sockets, _, __ = select.select(connected, [], [])
            for notified_socket in read_sockets:
                if notified_socket == client_recv_socket:
                    peer_socket, peer_addr = client_recv_socket.accept()
                    logging.debug(
                        msg=f"Accepted new connection from {peer_addr[0]}:{peer_addr[1]}",
                    )
                    try:
                        if ip_to_uname.get(peer_addr[0]) is None:
                            server_socket_mutex.lock("receive handler request uname")
                            peer_uname = request_uname(peer_addr[0], client_send_socket)
                            server_socket_mutex.unlock("receive handler request uname")
                            if peer_uname is not None:
                                connected.append(peer_socket)
                                ip_to_uname[peer_addr[0]] = peer_uname
                    except Exception as e:
                        logging.error(msg=e, exc_info=True)
                        break
                else:
                    try:
                        username = ip_to_uname[notified_socket.getpeername()[0]]
                        message_content: str = self.receive_msg(notified_socket)
                        message: Message = {"sender": username, "content": message_content}
                        if messages_store.get(username) is not None:
                            messages_store[username].append(message)
                        else:
                            messages_store[username] = [message]
                        self.message_received.emit(message)

                    except RequestException as e:
                        if e.code == ExceptionCode.DISCONNECT:
                            try:
                                connected.remove(notified_socket)
                            except ValueError:
                                logging.info("already removed")
                        logging.error(msg=f"Exception: {e.msg}")
                        break


class SendFileWorker(QObject):
    sending_file = pyqtSignal(dict)
    completed = pyqtSignal()

    def __init__(self, filepath: Path):
        global client_send_socket
        global server_socket_mutex
        super().__init__()
        self.filepath = filepath
        server_socket_mutex.lock("send file worker")
        peer_ip = ""
        if uname_to_ip.get(selected_uname) is None:
            peer_ip = request_ip(selected_uname, client_send_socket)
            uname_to_ip[selected_uname] = peer_ip
        else:
            peer_ip = uname_to_ip.get(selected_uname)

        server_socket_mutex.unlock("send file worker")
        if peer_ip is not None:
            self.client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_peer_socket.connect((peer_ip, CLIENT_RECV_PORT))

    def run(self):
        global self_uname
        if self.filepath and self.filepath.is_file():
            # self.filepath: Path = SHARE_FOLDER_PATH / self.filepath
            logging.debug(f"{self.filepath} chosen to send")
            filemetadata: FileMetadata = {
                "path": self.filepath.name,
                "size": self.filepath.stat().st_size,
            }
            logging.debug(filemetadata)
            filemetadata_bytes = msgpack.packb(filemetadata)
            logging.debug(filemetadata_bytes)
            filesend_header = (
                f"{HeaderCode.FILE.value}{len(filemetadata_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
            )
            try:
                file_to_send = self.filepath.open(mode="rb")
                logging.debug(f"Sending file {self.filepath} to {selected_uname}")
                self.client_peer_socket.send(filesend_header + filemetadata_bytes)
                total_bytes_read = 0
                msg = f"Sending file {str(self.filepath)}"
                if messages_store.get(selected_uname) is not None:
                    messages_store[selected_uname].append({"sender": self_uname, "content": msg})
                else:
                    messages_store[selected_uname] = [{"sender": self_uname, "content": msg}]
                self.sending_file.emit({"sender": self_uname, "content": msg})
                while total_bytes_read != filemetadata["size"]:
                    logging.debug(
                        f'sending file bytes {total_bytes_read} of {filemetadata["size"]}'
                    )
                    # time.sleep(0.1)
                    bytes_read = file_to_send.read(FILE_BUFFER_LEN)
                    self.client_peer_socket.sendall(bytes_read)
                    num_bytes = len(bytes_read)
                    total_bytes_read += num_bytes
                print("\nFile Sent")
                file_to_send.close()
            except Exception as e:
                logging.error(f"File Sending failed: {e}")
        else:
            logging.error(f"{self.filepath} not found")
            print(
                f"\nUnable to perform send request, ensure that the file is available in {user_settings['share_folder_path']}"
            )
        self.completed.emit()


class RequestFileSignals(QObject):
    receiving_new_file = pyqtSignal(Path)
    file_progress_update = pyqtSignal(Path)
    dir_progress_update = pyqtSignal(tuple)


class RequestFileWorker(QRunnable):
    def __init__(
        self, file_item: DirData, peer_ip: str, uname: str, parent_dir: Path | None
    ) -> None:
        super().__init__()
        self.file_item = file_item
        self.peer_ip = peer_ip
        self.uname = uname
        self.parent_dir = parent_dir
        self.worker_signals = RequestFileSignals()

        self.client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_peer_socket.connect((self.peer_ip, CLIENT_RECV_PORT))

        logging.debug(msg=f"Thread worker for requesting {uname}/{file_item['name']}")

    def run(self) -> str:
        global transfer_progress
        global user_settings
        # logging.debug(f"Requesting file, progress is {transfer_progress}")
        file_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        file_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        file_recv_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
        file_recv_socket.bind((CLIENT_IP, 0))
        file_recv_socket.listen()
        file_recv_port = file_recv_socket.getsockname()[1]

        offset = 0
        temp_path: Path = TEMP_FOLDER_PATH.joinpath(self.uname + "/" + self.file_item["path"])
        logging.debug(f"Using temp path {str(temp_path)}")
        if temp_path.exists():
            offset = temp_path.stat().st_size

        logging.debug(f"Offset of {offset} bytes")
        request_hash = self.file_item["hash"] is None
        file_request: FileRequest = {
            "port": file_recv_port,
            "filepath": self.file_item["path"],
            "request_hash": request_hash,
            "resume_offset": offset,
        }

        file_req_bytes = msgpack.packb(file_request)
        file_req_header = (
            f"{HeaderCode.FILE_REQUEST.value}{len(file_req_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
        )
        self.client_peer_socket.send(file_req_header + file_req_bytes)

        try:
            res_type = self.client_peer_socket.recv(HEADER_TYPE_LEN).decode(FMT)
            logging.debug(f"received header type {res_type} from sender")
            match res_type:
                case HeaderCode.FILE_REQUEST.value:
                    sender, _ = file_recv_socket.accept()
                    logging.debug(msg=f"Sender tried to connect: {sender.getpeername()}")
                    res_type = sender.recv(HEADER_TYPE_LEN).decode(FMT)
                    if res_type == HeaderCode.FILE.value:
                        file_header_len = int(sender.recv(HEADER_MSG_LEN).decode(FMT))
                        file_header: FileMetadata = msgpack.unpackb(sender.recv(file_header_len))
                        logging.debug(msg=f"receiving file with metadata {file_header}")
                        # Check if free disk space is available
                        if (
                            shutil.disk_usage(user_settings["downloads_folder_path"]).free
                            > file_header["size"]
                        ):
                            final_download_path: Path = get_unique_filename(
                                Path(user_settings["downloads_folder_path"]) / file_header["path"],
                                Path(user_settings["downloads_folder_path"]),
                            )
                            try:
                                temp_path.parent.mkdir(parents=True, exist_ok=True)
                                file_to_write = temp_path.open("ab")
                                # transfer_progress[temp_path] = {}
                                logging.debug(f"Creating and writing to {temp_path}")
                                try:
                                    byte_count = 0
                                    hash = hashlib.sha1()
                                    if transfer_progress.get(temp_path) is None:
                                        transfer_progress[temp_path] = {}
                                    # logging.debug(
                                    #     msg=f"transfer progress for {str(temp_path)} is {transfer_progress[temp_path]}"
                                    # )

                                    if (
                                        transfer_progress[temp_path].get(
                                            "status", TransferStatus.NEVER_STARTED
                                        )
                                        != TransferStatus.PAUSED
                                    ):
                                        transfer_progress[temp_path][
                                            "status"
                                        ] = TransferStatus.DOWNLOADING
                                    if offset == 0:
                                        if self.parent_dir is None:
                                            self.worker_signals.receiving_new_file.emit(temp_path)
                                    while True:
                                        if (
                                            transfer_progress[temp_path]["status"]
                                            == TransferStatus.PAUSED
                                        ):
                                            file_to_write.close()
                                            file_recv_socket.close()
                                            return f"Download for file {file_header['path']} was paused"
                                        file_bytes_read: bytes = sender.recv(FILE_BUFFER_LEN)
                                        if not offset:
                                            hash.update(file_bytes_read)
                                        num_bytes_read = len(file_bytes_read)
                                        byte_count += num_bytes_read
                                        transfer_progress[temp_path]["progress"] = byte_count
                                        transfer_progress[temp_path]["percent_progress"] = (
                                            100 * byte_count / file_header["size"]
                                        )
                                        file_to_write.write(file_bytes_read)
                                        # logging.debug(
                                        #     msg=f"Received chunk of size {num_bytes_read}, received {byte_count} of {file_header['size']}"
                                        # )
                                        if self.parent_dir is None:
                                            self.worker_signals.file_progress_update.emit(temp_path)
                                        else:
                                            self.worker_signals.dir_progress_update.emit(
                                                (self.parent_dir, num_bytes_read)
                                            )
                                        if num_bytes_read == 0:
                                            break

                                    hash_str = ""
                                    if offset:
                                        file_to_write.seek(0)
                                        hash_str = get_file_hash(str(temp_path))
                                    file_to_write.close()

                                    received_hash = hash.hexdigest() if not offset else hash_str
                                    if (request_hash and received_hash == file_header["hash"]) or (
                                        received_hash == self.file_item["hash"]
                                    ):
                                        transfer_progress[temp_path][
                                            "status"
                                        ] = TransferStatus.COMPLETED
                                        final_download_path.parent.mkdir(
                                            parents=True, exist_ok=True
                                        )
                                        shutil.move(temp_path, final_download_path)
                                        print("Succesfully received 1 file")
                                    else:
                                        transfer_progress[temp_path][
                                            "status"
                                        ] = TransferStatus.FAILED
                                        logging.error(
                                            msg=f"Failed integrity check for file {file_header['path']}"
                                        )
                                except Exception as e:
                                    logging.error(e, exc_info=True)
                                    print("File received but failed to save")
                            except Exception as e:
                                logging.error(e, exc_info=True)
                                print("Unable to write file")
                        else:
                            logging.error(
                                msg=f"Not enough space to receive file {file_header['path']}, {file_header['size']}"
                            )
                    else:
                        raise RequestException(
                            f"Sender sent invalid message type in header: {res_type}",
                            ExceptionCode.INVALID_HEADER,
                        )
                case HeaderCode.ERROR.value:
                    res_len = int(self.client_peer_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                    res = self.client_peer_socket.recv(res_len)
                    err: RequestException = msgpack.unpackb(
                        res,
                        object_hook=RequestException.from_dict,
                        raw=False,
                    )
                    raise err
                case _:
                    err = RequestException(
                        f"Invalid message type in header: {res_type}",
                        ExceptionCode.INVALID_HEADER,
                    )
                    raise err
        except UnicodeDecodeError as e:
            logging.error(f"UnicodeDecodeError: {e}")
            # raise RequestException("Invalid message type in header", ExceptionCode.INVALID_HEADER)
        except Exception as e:
            logging.error(e, exc_info=True)
            # raise e


class Ui_DrizzleMainWindow(QWidget):
    global client_send_socket
    global client_recv_socket
    global uname_to_status

    def __init__(self, MainWindow):
        super(Ui_DrizzleMainWindow, self).__init__()
        try:
            global user_settings
            self.user_settings = MainWindow.user_settings
            user_settings = MainWindow.user_settings
            SERVER_IP = self.user_settings["server_ip"]
            SERVER_ADDR = (SERVER_IP, SERVER_RECV_PORT)
            client_send_socket.settimeout(10)
            client_send_socket.connect(SERVER_ADDR)
            client_send_socket.settimeout(None)
            self_uname = self.user_settings["uname"]
            username = self_uname.encode(FMT)
            username_header = (
                f"{HeaderCode.NEW_CONNECTION.value}{len(username):<{HEADER_MSG_LEN}}".encode(FMT)
            )
            client_send_socket.send(username_header + username)
            type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
            if type != HeaderCode.NEW_CONNECTION.value:
                error_len = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                error = client_send_socket.recv(error_len)
                exception: RequestException = msgpack.unpackb(
                    error, object_hook=RequestException.from_dict, raw=False
                )
                if exception.code == ExceptionCode.USER_EXISTS:
                    logging.error(msg=exception.msg)
                    print("\nSorry that username is taken, please choose another one")
                    error_dialog = QDialog()
                    error_dialog.ui = Ui_ErrorDialog(
                        error_dialog,
                        "Sorry that username is taken, please choose another one",
                        self.user_settings,
                    )
                    error_dialog.exec()

                else:
                    logging.fatal(msg=exception.msg)
                    print("\nSorry something went wrong")
                    client_send_socket.close()
                    client_recv_socket.close()
                    MainWindow.close()
            update_share_data(Path(self.user_settings["share_folder_path"]), client_send_socket)

            self.heartbeat_thread = QThread()
            self.heartbeat_worker = HeartbeatWorker(self.user_settings)
            self.heartbeat_worker.moveToThread(self.heartbeat_thread)
            self.heartbeat_thread.started.connect(self.heartbeat_worker.run)
            self.heartbeat_worker.update_status.connect(self.update_online_status)
            self.heartbeat_thread.start()

            self.receive_thread = QThread()
            self.receive_worker = ReceiveHandler()
            self.receive_worker.moveToThread(self.receive_thread)
            self.receive_thread.started.connect(self.receive_worker.run)
            self.receive_worker.message_received.connect(self.messages_controller)
            self.receive_thread.start()

        except Exception as e:
            logging.error(f"Could not connect to server: {e}")
            error_dialog = QDialog()
            error_dialog.ui = Ui_ErrorDialog(
                error_dialog,
                f"Could not connect to server: {e}\nEnsure that the server is online and you have entered the correct server IP.",
                self.user_settings,
            )
            sys.exit(error_dialog.exec())

        self.setupUi(MainWindow)

    def send_message(self):
        global client_send_socket
        global client_recv_socket
        global messages_store
        global server_socket_mutex
        global selected_uname

        if self.txtedit_MessageInput.toPlainText() == "":
            return
        server_socket_mutex.lock("send message")
        peer_ip = ""
        if uname_to_ip.get(selected_uname) is None:
            peer_ip = request_ip(selected_uname, client_send_socket)
            uname_to_ip[selected_uname] = peer_ip
        else:
            peer_ip = uname_to_ip.get(selected_uname)
        server_socket_mutex.unlock("send message")
        client_peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_peer_socket.connect((peer_ip, CLIENT_RECV_PORT))
        if peer_ip is not None:
            msg = self.txtedit_MessageInput.toPlainText()
            msg_bytes = msg.encode(FMT)
            header = f"{HeaderCode.MESSAGE.value}{len(msg_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
            try:
                client_peer_socket.send(header + msg_bytes)
                if messages_store.get(selected_uname) is not None:
                    messages_store[selected_uname].append({"sender": self_uname, "content": msg})
                else:
                    messages_store[selected_uname] = [{"sender": self_uname, "content": msg}]
                self.render_messages(messages_store[selected_uname])
            except Exception as e:
                logging.error(f"Failed to send message: {e}")
            finally:
                self.txtedit_MessageInput.clear()
        else:
            logging.error(f"Could not find ip for user {selected_uname}")

    def closeEvent(self, event) -> None:
        self.heartbeat_thread.exit()
        return super().closeEvent(event)

    def render_file_tree(self, share: list[DirData] | None, parent: QTreeWidgetItem):
        if share is None:
            return
        for item in share:
            if item["type"] == "file":
                file_item = QTreeWidgetItem(parent)
                file_item.setText(0, item["name"])
                file_item.setData(0, Qt.UserRole, item)
            else:
                dir_item = QTreeWidgetItem(parent)
                dir_item.setText(0, item["name"] + "/")
                dir_item.setData(0, Qt.UserRole, item)
                self.render_file_tree(item["children"], dir_item)

    def on_file_item_selected(self):
        global selected_file_items
        selected_items = self.file_tree.selectedItems()
        selected_file_items = []
        for item in selected_items:
            data: DirData = item.data(0, Qt.UserRole)
            selected_file_items.append(data)
        if len(selected_items) == 1:
            self.lbl_FileInfo.setText(selected_file_items[0]["name"])
            self.btn_FileInfo.setEnabled(True)
        else:
            self.lbl_FileInfo.setText(f"{len(selected_items)} items selected")
            self.btn_FileInfo.setEnabled(False)

    def show_file_info_dialog(self, MainWindow):
        global selected_file_items
        selected_item = selected_file_items[0]
        size = selected_item["size"]
        item_info = {
            "name": selected_item["name"],
            "hash": selected_item["hash"] or "Not available",
            "type": selected_item["type"],
            "size": convert_size(size or 0),
        }
        if selected_item["type"] != "file":
            size, count = get_directory_size(selected_item, 0, 0)
            item_info["size"] = convert_size(size)
            item_info["count"] = f"{count} files"
        message_box = QMessageBox(MainWindow)
        message_box.setIcon(QMessageBox.Information)
        message_box.setWindowTitle("File Info")
        message_box.setText(selected_item["name"])
        message_box.setInformativeText(json.dumps(item_info, indent=4, sort_keys=True))
        message_box.addButton(QMessageBox.Close)
        message_box.exec()

    def download_files(self):
        global selected_uname
        global client_send_socket
        global transfer_progress
        global selected_file_items
        global server_socket_mutex
        global uname_to_ip

        request_file_pool = QThreadPool.globalInstance()
        request_file_pool.setMaxThreadCount(4)

        for selected_item in selected_file_items:
            server_socket_mutex.lock("download files")
            peer_ip = ""
            if uname_to_ip.get(selected_uname) is None:
                peer_ip = request_ip(selected_uname, client_send_socket)
                uname_to_ip[selected_uname] = peer_ip
            else:
                peer_ip = uname_to_ip.get(selected_uname)
            server_socket_mutex.unlock("download files")
            if peer_ip is None:
                logging.error(f"Selected user {selected_uname} does not exist")
                return
                # TODO: add error dialog

            transfer_progress[TEMP_FOLDER_PATH / selected_uname / selected_item["path"]] = {
                "progress": 0,
                "status": TransferStatus.NEVER_STARTED,
            }
            if selected_item["type"] == "file":
                request_file_worker = RequestFileWorker(
                    selected_item, peer_ip, selected_uname, None
                )
                request_file_worker.worker_signals.receiving_new_file.connect(
                    self.new_file_progress
                )
                request_file_worker.worker_signals.file_progress_update.connect(
                    self.update_file_progress
                )
                request_file_pool.start(request_file_worker)
            else:
                files_to_request: list[DirData] = []
                get_files_in_dir(
                    selected_item["children"],
                    files_to_request,
                )
                dir_path = TEMP_FOLDER_PATH / selected_uname / selected_item["path"]
                dir_progress[dir_path] = {
                    "current": 0,
                    "total": get_directory_size(selected_item, 0, 0)[0],
                    "status": TransferStatus.DOWNLOADING,
                    "mutex": QMutex(),
                }
                self.new_file_progress(dir_path)
                for f in files_to_request:
                    transfer_progress[TEMP_FOLDER_PATH / selected_uname / f["path"]] = {
                        "progress": 0,
                        "status": TransferStatus.NEVER_STARTED,
                    }
                for file in files_to_request:
                    request_file_worker = RequestFileWorker(file, peer_ip, selected_uname, dir_path)
                    request_file_worker.worker_signals.dir_progress_update.connect(
                        self.update_dir_progress
                    )
                    request_file_pool.start(request_file_worker)

    def construct_message_html(self, message: Message, is_self: bool):
        return f"""<p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">
<span style=" font-weight:600; color:{'#1a5fb4' if is_self else '#e5a50a'};">{"You" if is_self else message["sender"]}: </span>
{message["content"]}
</p>
        """

    def messages_controller(self, message: Message):
        global selected_uname
        global self_uname
        if message["sender"] == selected_uname:
            self.render_messages(messages_store[selected_uname])

    def render_messages(self, messages_list: list[Message]):
        global self_uname
        if messages_list is None or messages_list == []:
            self.txtedit_MessagesArea.clear()
            return
        messages_html = LEADING_HTML
        for message in messages_list:
            messages_html += self.construct_message_html(message, message["sender"] == self_uname)
        messages_html += TRAILING_HTML
        self.txtedit_MessagesArea.setHtml(messages_html)
        self.txtedit_MessagesArea.verticalScrollBar().setValue(
            self.txtedit_MessagesArea.verticalScrollBar().maximum()
        )

    def update_online_status(self, new_status: dict[str, int]):
        global uname_to_status
        old_users = set(uname_to_status.keys())
        new_users = set(new_status.keys())
        to_add = new_users.difference(old_users)
        users_to_remove = old_users.difference(new_users)

        for index in range(self.lw_OnlineStatus.count()):
            item = self.lw_OnlineStatus.item(index)
            username = item.data(Qt.UserRole)  # type: ignore
            if username in users_to_remove:
                item.setIcon(self.icon_Offline)
                timestamp = time.localtime(uname_to_status[username])
                item.setText(
                    username + (f" (last active: {time.strftime('%d-%m-%Y %H:%M:%S', timestamp)})")
                )
            else:
                item.setIcon(
                    self.icon_Online
                    if time.time() - new_status[username] <= ONLINE_TIMEOUT
                    else self.icon_Offline
                )
                timestamp = time.localtime(new_status[username])
                item.setText(
                    username
                    + (
                        ""
                        if time.time() - new_status[username] <= ONLINE_TIMEOUT
                        else f" (last active: {time.strftime('%d-%m-%Y %H:%M:%S', timestamp)})"
                    )
                )

        for uname in to_add:
            status_item = QListWidgetItem(self.lw_OnlineStatus)
            status_item.setIcon(
                self.icon_Online
                if time.time() - new_status[uname] <= ONLINE_TIMEOUT
                else self.icon_Offline
            )
            timestamp = time.localtime(new_status[uname])
            status_item.setData(Qt.UserRole, uname)  # type: ignore
            status_item.setText(
                uname + ""
                if time.time() - new_status[uname] <= ONLINE_TIMEOUT
                else f" (last active: {time.strftime('%d-%m-%Y %H:%M:%S', timestamp)})"
            )
        uname_to_status = new_status

    def on_user_selected(self):
        global selected_uname
        global server_socket_mutex

        items = self.lw_OnlineStatus.selectedItems()
        if len(items):
            item = items[0]
            username: str = item.data(Qt.UserRole)
            selected_uname = username
            self.render_messages(messages_store.get(selected_uname))
            self.btn_SendMessage.setEnabled(
                True if time.time() - uname_to_status[username] < ONLINE_TIMEOUT else False
            )
            self.btn_SendFile.setEnabled(
                True if time.time() - uname_to_status[username] < ONLINE_TIMEOUT else False
            )
            if time.time() - uname_to_status[username] > ONLINE_TIMEOUT:
                self.file_tree.clear()
                self.file_tree.headerItem().setText(0, "Selected user is offline")
                return
            searchquery_bytes = username.encode(FMT)
            search_header = (
                f"{HeaderCode.FILE_SEARCH.value}{len(searchquery_bytes):<{HEADER_MSG_LEN}}".encode(
                    FMT
                )
            )
            server_socket_mutex.lock("file search")
            client_send_socket.send(search_header + searchquery_bytes)
            response_header_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
            if response_header_type == HeaderCode.FILE_SEARCH.value:
                response_len = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                browse_files: list[DBData] = msgpack.unpackb(
                    recvall(client_send_socket, response_len),
                )
                server_socket_mutex.unlock("file search")
                if len(browse_files):
                    self.file_tree.clear()
                    self.file_tree.headerItem().setText(0, username)
                    self.render_file_tree(browse_files[0]["share"], self.file_tree)
                else:
                    print("No files found")
            else:
                server_socket_mutex.unlock("file search")
                logging.error(f"Error occured while searching for files, {response_header_type}")
                error_dialog = QDialog()
                error_dialog.ui = Ui_ErrorDialog(
                    error_dialog,
                    f"Error occured while searching for files, {response_header_type}",
                    self.user_settings,
                )
                error_dialog.exec()

    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName("MainWindow")
        MainWindow.resize(881, 744)
        sizePolicy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setUnifiedTitleAndToolBarOnMac(False)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_4 = QVBoxLayout(self.centralwidget)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.verticalLayout.setSizeConstraint(QLayout.SetMaximumSize)
        self.verticalLayout.setContentsMargins(10, 0, 10, -1)
        self.Buttons = QHBoxLayout()
        self.Buttons.setSpacing(6)
        self.Buttons.setObjectName("Buttons")
        self.Buttons.setSizeConstraint(QLayout.SetDefaultConstraint)
        self.label_3 = QLabel(self.centralwidget)
        self.label_3.setObjectName("label_3")
        sizePolicy1 = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.label_3.sizePolicy().hasHeightForWidth())
        self.label_3.setSizePolicy(sizePolicy1)
        font = QFont()
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setMargin(0)

        self.Buttons.addWidget(self.label_3)

        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.Buttons.addItem(self.horizontalSpacer)

        self.btn_AddFiles = QPushButton(self.centralwidget)
        self.btn_AddFiles.setObjectName("pushButton_2")
        self.btn_AddFiles.clicked.connect(self.import_files)

        self.btn_AddFolder = QPushButton(self.centralwidget)
        self.btn_AddFolder.setObjectName("pushButton_2")
        self.btn_AddFolder.clicked.connect(self.import_folder)

        self.Buttons.addWidget(self.btn_AddFiles)
        self.Buttons.addWidget(self.btn_AddFolder)

        self.btn_Settings = QPushButton(self.centralwidget)
        self.btn_Settings.setObjectName("pushButton")

        self.Buttons.addWidget(self.btn_Settings)

        self.verticalLayout.addLayout(self.Buttons)

        self.Content = QHBoxLayout()
        self.Content.setObjectName("Content")
        self.Files = QVBoxLayout()
        self.Files.setObjectName("Files")
        self.label = QLabel(self.centralwidget)
        self.label.setObjectName("label")

        self.Files.addWidget(self.label)

        self.file_tree = QTreeWidget(self.centralwidget)
        # self.file_tree.itemClicked.connect(self.on_file_item_selected)
        self.file_tree.itemSelectionChanged.connect(self.on_file_item_selected)
        self.file_tree.header().setVisible(True)
        self.file_tree.headerItem().setText(0, "No user selected")
        self.file_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)

        self.Files.addWidget(self.file_tree)

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.lbl_FileInfo = QLabel(self.centralwidget)
        self.lbl_FileInfo.setObjectName("label_4")

        self.horizontalLayout_2.addWidget(self.lbl_FileInfo)

        self.horizontalSpacer_2 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer_2)

        self.btn_FileInfo = QPushButton(self.centralwidget)
        self.btn_FileInfo.setObjectName("pushButton_5")
        self.btn_FileInfo.setEnabled(True)
        self.btn_FileInfo.clicked.connect(lambda: self.open_file_info(MainWindow))

        self.horizontalLayout_2.addWidget(self.btn_FileInfo)

        self.btn_FileDownload = QPushButton(self.centralwidget)
        self.btn_FileDownload.setObjectName("pushButton_4")
        self.btn_FileDownload.setEnabled(True)
        self.btn_FileDownload.clicked.connect(self.download_files)

        self.horizontalLayout_2.addWidget(self.btn_FileDownload)

        self.Files.addLayout(self.horizontalLayout_2)

        self.Files.setStretch(1, 2)

        self.Content.addLayout(self.Files)

        self.Users = QVBoxLayout()
        self.Users.setObjectName("Users")
        self.Users.setSizeConstraint(QLayout.SetDefaultConstraint)
        self.label_2 = QLabel(self.centralwidget)
        self.label_2.setObjectName("label_2")

        self.Users.addWidget(self.label_2)

        self.lw_OnlineStatus = QListWidget(self.centralwidget)
        self.lw_OnlineStatus.setSelectionMode(QAbstractItemView.SingleSelection)
        self.lw_OnlineStatus.itemSelectionChanged.connect(self.on_user_selected)
        self.icon_Online = QIcon()
        self.icon_Online.addFile("ui/res/earth.png", QSize(), QIcon.Normal, QIcon.Off)

        self.icon_Offline = QIcon()
        self.icon_Offline.addFile("ui/res/web-off.png", QSize(), QIcon.Normal, QIcon.Off)

        self.lw_OnlineStatus.setObjectName("listWidget")
        self.lw_OnlineStatus.setSortingEnabled(False)

        self.Users.addWidget(self.lw_OnlineStatus)

        self.txtedit_MessagesArea = QTextEdit(self.centralwidget)
        self.txtedit_MessagesArea.setObjectName("textEdit")
        sizePolicy2 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        sizePolicy2.setHorizontalStretch(0)
        sizePolicy2.setVerticalStretch(5)
        sizePolicy2.setHeightForWidth(self.txtedit_MessagesArea.sizePolicy().hasHeightForWidth())
        self.txtedit_MessagesArea.setSizePolicy(sizePolicy2)
        self.txtedit_MessagesArea.setMinimumSize(QSize(0, 0))
        self.txtedit_MessagesArea.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.Users.addWidget(self.txtedit_MessagesArea)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.horizontalLayout.setSizeConstraint(QLayout.SetDefaultConstraint)

        self.txtedit_MessageInput = QPlainTextEdit(self.centralwidget)
        self.txtedit_MessageInput.setObjectName("plainTextEdit")
        self.txtedit_MessageInput.setEnabled(True)
        sizePolicy3 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        sizePolicy3.setHorizontalStretch(0)
        sizePolicy3.setVerticalStretch(0)
        sizePolicy3.setHeightForWidth(self.txtedit_MessageInput.sizePolicy().hasHeightForWidth())
        self.txtedit_MessageInput.setSizePolicy(sizePolicy3)
        self.txtedit_MessageInput.setMaximumSize(QSize(16777215, 80))

        self.horizontalLayout.addWidget(self.txtedit_MessageInput)

        self.verticalLayout_6 = QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.btn_SendMessage = QPushButton(self.centralwidget)
        self.btn_SendMessage.setObjectName("pushButton_3")
        self.btn_SendMessage.setEnabled(False)
        sizePolicy4 = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        sizePolicy4.setHorizontalStretch(0)
        sizePolicy4.setVerticalStretch(0)
        sizePolicy4.setHeightForWidth(self.btn_SendMessage.sizePolicy().hasHeightForWidth())
        self.btn_SendMessage.setSizePolicy(sizePolicy4)
        self.btn_SendMessage.clicked.connect(self.send_message)

        self.verticalLayout_6.addWidget(self.btn_SendMessage)

        self.btn_SendFile = QPushButton(self.centralwidget)
        self.btn_SendFile.setObjectName("pushButton_6")
        sizePolicy4.setHeightForWidth(self.btn_SendFile.sizePolicy().hasHeightForWidth())
        self.btn_SendFile.setSizePolicy(sizePolicy4)
        self.btn_SendFile.setEnabled(False)
        self.btn_SendFile.clicked.connect(self.share_file)

        self.verticalLayout_6.addWidget(self.btn_SendFile)

        self.horizontalLayout.addLayout(self.verticalLayout_6)

        self.Users.addLayout(self.horizontalLayout)

        self.Users.setStretch(1, 4)
        self.Users.setStretch(3, 1)

        self.Content.addLayout(self.Users)

        self.Content.setStretch(0, 3)
        self.Content.setStretch(1, 2)

        self.verticalLayout.addLayout(self.Content)

        self.label_12 = QLabel(self.centralwidget)
        self.label_12.setObjectName("label_12")

        self.verticalLayout.addWidget(self.label_12)

        self.scroll_FileProgress = QScrollArea(self.centralwidget)
        self.scroll_FileProgress.setObjectName("scrollArea")
        sizePolicy5 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.MinimumExpanding)
        sizePolicy5.setHorizontalStretch(0)
        sizePolicy5.setVerticalStretch(0)
        sizePolicy5.setHeightForWidth(self.scroll_FileProgress.sizePolicy().hasHeightForWidth())
        self.scroll_FileProgress.setSizePolicy(sizePolicy5)
        # self.scroll_FileProgress.setMaximumSize(QSize(16777215, 250))
        self.scroll_FileProgress.setMinimumSize(QSize(0, 150))
        self.scroll_FileProgress.setWidgetResizable(True)
        self.scrollContents_FileProgress = QWidget()
        self.scrollContents_FileProgress.setObjectName("scrollAreaWidgetContents")
        self.scrollContents_FileProgress.setGeometry(QRect(0, 0, 831, 328))
        self.vBoxLayout_ScrollContents = QVBoxLayout(self.scrollContents_FileProgress)
        self.vBoxLayout_ScrollContents.setObjectName("verticalLayout_5")
        self.vBoxLayout_ScrollContents.setAlignment(Qt.AlignTop)

        # self.widget_6 = QWidget(self.scrollContents_FileProgress)
        # self.widget_6.setObjectName("widget_6")
        # sizePolicy6 = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        # sizePolicy6.setHorizontalStretch(0)
        # sizePolicy6.setVerticalStretch(0)
        # sizePolicy6.setHeightForWidth(self.widget_6.sizePolicy().hasHeightForWidth())
        # self.widget_6.setSizePolicy(sizePolicy6)
        # self.widget_6.setMinimumSize(QSize(0, 40))
        # self.widget_6.setMaximumSize(QSize(16777215, 40))
        # self.horizontalLayout_8 = QHBoxLayout(self.widget_6)
        # self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        # self.label_10 = QLabel(self.widget_6)
        # self.label_10.setObjectName("label_10")

        self.scroll_FileProgress.setWidget(self.scrollContents_FileProgress)

        self.verticalLayout.addWidget(self.scroll_FileProgress)

        self.verticalLayout_4.addLayout(self.verticalLayout)

        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)

        QMetaObject.connectSlotsByName(MainWindow)

    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", "Drizzle", None))
        self.label_3.setText(
            QCoreApplication.translate(
                "MainWindow", f"Drizzle / {self.user_settings['uname']}", None
            )
        )
        self.btn_AddFiles.setText(QCoreApplication.translate("MainWindow", "Add Files", None))
        self.btn_AddFolder.setText(QCoreApplication.translate("MainWindow", "Add Folder", None))
        self.btn_Settings.setText(QCoreApplication.translate("MainWindow", "Settings", None))
        self.label.setText(QCoreApplication.translate("MainWindow", "Browse Files", None))

        self.btn_Settings.clicked.connect(lambda: self.open_settings(MainWindow))

        __sortingEnabled = self.file_tree.isSortingEnabled()
        self.file_tree.setSortingEnabled(__sortingEnabled)

        self.lbl_FileInfo.setText(
            QCoreApplication.translate("MainWindow", "No file or folder selected", None)
        )
        self.btn_FileInfo.setText(QCoreApplication.translate("MainWindow", "Info", None))
        self.btn_FileDownload.setText(QCoreApplication.translate("MainWindow", "Download", None))
        self.label_2.setText(QCoreApplication.translate("MainWindow", "Users", None))

        __sortingEnabled1 = self.lw_OnlineStatus.isSortingEnabled()
        self.lw_OnlineStatus.setSortingEnabled(False)
        self.lw_OnlineStatus.setSortingEnabled(__sortingEnabled1)

        self.txtedit_MessageInput.setPlaceholderText(
            QCoreApplication.translate("MainWindow", "Enter message", None)
        )
        self.btn_SendMessage.setText(QCoreApplication.translate("MainWindow", "Send Message", None))
        self.btn_SendFile.setText(QCoreApplication.translate("MainWindow", "Send File", None))
        self.label_12.setText(QCoreApplication.translate("MainWindow", "Downloading:", None))

    def open_settings(self, MainWindow):
        settings_dialog = QDialog(MainWindow)
        settings_dialog.ui = Ui_SettingsDialog(settings_dialog, self.user_settings)
        settings_dialog.exec()

    def open_file_info(self, MainWindow):
        global selected_file_items
        global selected_uname
        selected_item = selected_file_items[0]
        size = selected_item["size"]
        filedata = {
            "name": selected_item["name"],
            "hash": selected_item["hash"] or "Not available",
            "type": selected_item["type"],
            "size": convert_size(size or 0),
            "owner": selected_uname,
        }
        if selected_item["type"] != "file":
            size, count = get_directory_size(selected_item, 0, 0)
            filedata["size"] = convert_size(size)
            filedata["count"] = f"{count} files"
        file_info_dialog = QDialog(MainWindow)
        file_info_dialog.ui = Ui_FileInfoDialog(file_info_dialog, filedata)
        file_info_dialog.exec()

    def import_files(self):
        global server_socket_mutex
        files, _ = QFileDialog.getOpenFileNames(
            self, "Import Files", str(Path.home()), "All Files (*)"
        )
        for file in files:
            imported = import_file_to_share(
                Path(file), Path(self.user_settings["share_folder_path"])
            )
            if imported is not None:
                print(f"Imported file {imported}")
        server_socket_mutex.lock("import files")
        update_share_data(Path(self.user_settings["share_folder_path"]), client_send_socket)
        server_socket_mutex.unlock("import files")

    def import_folder(self):
        global server_socket_mutex

        dir = QFileDialog.getExistingDirectory(
            self, "Import Folder", str(Path.home()), QFileDialog.ShowDirsOnly
        )
        if dir == "":
            return
        imported = import_file_to_share(Path(dir), Path(self.user_settings["share_folder_path"]))
        if imported is not None:
            print(f"Imported file {imported}")
        server_socket_mutex.lock("import folder")
        update_share_data(Path(self.user_settings["share_folder_path"]), client_send_socket)
        server_socket_mutex.unlock("import folder")

    def share_file(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Import Files", str(Path.home()), "All Files (*)"
        )
        if filepath == "":
            return
        self.send_file_thread = QThread()
        self.send_file_worker = SendFileWorker(Path(filepath))
        self.send_file_worker.moveToThread(self.send_file_thread)
        self.send_file_thread.started.connect(self.send_file_worker.run)
        self.send_file_worker.sending_file.connect(self.messages_controller)
        self.send_file_worker.completed.connect(self.send_file_thread.quit)
        self.send_file_worker.completed.connect(self.send_file_worker.deleteLater)
        self.send_file_thread.finished.connect(self.send_file_thread.deleteLater)

        self.send_file_thread.start()

    def new_file_progress(self, path: Path):
        logging.debug(msg="New file progress")
        global progress_widgets
        file_progress_widget = QWidget(self.scrollContents_FileProgress)
        file_progress_widget.ui = Ui_FileProgressWidget(file_progress_widget, path)
        self.vBoxLayout_ScrollContents.addWidget(file_progress_widget)
        progress_widgets[path] = file_progress_widget

    def update_file_progress(self, path: Path):
        global transfer_progress
        global progress_widgets
        progress_widgets[path].ui.update_progress(transfer_progress[path]["percent_progress"])

    def update_dir_progress(self, progress_data: tuple[Path, int]):
        global dir_progress
        global progress_widgets
        path, increment = progress_data
        dir_progress[path]["mutex"].lock("update dir progress")
        dir_progress[path]["current"] += increment
        progress_widgets[path].ui.update_progress(
            100 * dir_progress[path]["current"] / dir_progress[path]["total"]
        )
        dir_progress[path]["mutex"].unlock("update dir progress")
