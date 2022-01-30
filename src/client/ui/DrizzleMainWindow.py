import json
import logging
import select
import socket
import sys
import threading
import time
from pathlib import Path

import msgpack
from PyQt5.QtCore import *
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import *
from ui.ErrorDialog import Ui_ErrorDialog
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
    RECV_FOLDER_PATH,
    SERVER_RECV_PORT,
    SHARE_FOLDER_PATH,
    TRAILING_HTML,
)
from utils.exceptions import ExceptionCode, RequestException
from utils.helpers import (
    convert_size,
    get_directory_size,
    get_file_hash,
    get_unique_filename,
    import_file_to_share,
    path_to_dict,
)
from utils.socket_functions import get_ip, recvall, request_ip, update_share_data
from utils.types import (
    DBData,
    DirData,
    FileMetadata,
    FileRequest,
    HeaderCode,
    Message,
    UpdateHashParams,
    UserSettings,
)

SERVER_IP = ""
SERVER_ADDR = ()
CLIENT_IP = get_ip()


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
selected_file_item: DirData = {}
self_uname: str = ""


class HeartbeatWorker(QObject):
    update_status = pyqtSignal(dict)

    def __init__(self, settings: UserSettings):
        super(HeartbeatWorker, self).__init__()
        self.settings = settings

    def run(self):
        global client_send_socket
        heartbeat = HeaderCode.HEARTBEAT_REQUEST.value.encode(FMT)
        while True:
            time.sleep(HEARTBEAT_TIMER)
            client_send_socket.send(heartbeat)
            type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)

            if type == HeaderCode.HEARTBEAT_REQUEST.value:
                length = int(client_send_socket.recv((HEADER_MSG_LEN)).decode(FMT))
                new_status = msgpack.unpackb(client_send_socket.recv(length))
                self.update_status.emit(new_status)
            else:
                logging.error(
                    f"Server sent invalid message type in header: {type}",
                )
                error_dialog = QDialog()
                error_dialog.ui = Ui_ErrorDialog(
                    error_dialog, f"Cannot establish connection with server", self.settings
                )
                sys.exit(error_dialog.exec())


class ReceiveHandler(QObject):
    message_received = pyqtSignal(dict)

    def send_file(
        self,
        filepath: Path,
        requester: tuple[str, int],
        request_hash: bool,
        resume_offset: int,
    ) -> None:
        file_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        file_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        file_send_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
        file_send_socket.connect(requester)
        hash = ""
        # compression = CompressionMethod.NONE

        # file_size = filepath.stat().st_size
        # if file_size < COMPRESSION_THRESHOLD:
        #     compression = CompressionMethod.ZSTD
        #     compressor = zstd.ZstdCompressor()
        #     with filepath.open(mode="rb") as uncompressed_file:
        #         with compressor.stream_writer(uncompressed_file) as writer:
        #             pass
        if request_hash:
            hash = get_file_hash(str(filepath))

        filemetadata: FileMetadata = {
            "path": str(filepath).removeprefix(str(SHARE_FOLDER_PATH) + "/"),
            "size": filepath.stat().st_size,
            "hash": hash if request_hash else None,
            # "compression": compression,
        }

        logging.debug(filemetadata)
        filemetadata_bytes = msgpack.packb(filemetadata)
        logging.debug(filemetadata_bytes)
        filesend_header = (
            f"{HeaderCode.FILE.value}{len(filemetadata_bytes):<{HEADER_MSG_LEN}}".encode(FMT)
        )

        try:
            file_to_send = filepath.open(mode="rb")
            logging.debug(f"Sending file {filemetadata['path']} to {requester}")
            file_send_socket.send(filesend_header + filemetadata_bytes)

            total_bytes_read = 0
            file_to_send.seek(resume_offset)
            while total_bytes_read != filemetadata["size"] - resume_offset:
                time.sleep(0.05)
                bytes_read = file_to_send.read(FILE_BUFFER_LEN)
                num_bytes = file_send_socket.send(bytes_read)
                total_bytes_read += num_bytes
                print("\nFile Sent")
                file_to_send.close()
                file_send_socket.close()
            if request_hash:
                update_hash_params: UpdateHashParams = {
                    "filepath": str(filepath).removeprefix(str(SHARE_FOLDER_PATH) + "/"),
                    "hash": hash,
                }
                update_hash_bytes = msgpack.packb(update_hash_params)
                update_hash_header = f"{HeaderCode.UPDATE_HASH.value}{len(update_hash_bytes):<{HEADER_MSG_LEN}}".encode(
                    FMT
                )
                client_send_socket.send(update_hash_header + update_hash_bytes)
        except Exception as e:
            logging.error(f"File Sending failed: {e}")

    def receive_msg(self, socket: socket.socket) -> str:
        global client_send_socket
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
                    write_path: Path = get_unique_filename(RECV_FOLDER_PATH / file_header["path"])
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
                            return "Succesfully received 1 file"
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
                    requested_file_path = SHARE_FOLDER_PATH / file_req_header["filepath"]
                    if requested_file_path.is_file():
                        socket.send(HeaderCode.FILE_REQUEST.value.encode(FMT))
                        send_file_thread = threading.Thread(
                            target=self.send_file,
                            args=(
                                requested_file_path,
                                (socket.getpeername()[0], file_req_header["port"]),
                                file_req_header["request_hash"],
                                file_req_header["resume_offset"],
                            ),
                        )
                        send_file_thread.start()
                        return "File requested by user"
                    elif requested_file_path.is_dir():
                        raise RequestException(
                            f"Requested a directory, {file_req_header['filepath']} is not a file.",
                            ExceptionCode.BAD_REQUEST,
                        )
                    else:
                        share_data = msgpack.packb(path_to_dict(SHARE_FOLDER_PATH)["children"])
                        share_data_header = f"{HeaderCode.SHARE_DATA.value}{len(share_data):<{HEADER_MSG_LEN}}".encode(
                            FMT
                        )
                        client_send_socket.sendall(share_data_header + share_data)
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
        peers: dict[str, str] = {}

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
                        connected.append(peer_socket)
                        lookup = peer_addr[0].encode(FMT)
                        header = f"{HeaderCode.REQUEST_UNAME.value}{len(lookup):<{HEADER_MSG_LEN}}".encode(
                            FMT
                        )
                        logging.debug(msg=f"Sending packet {(header + lookup).decode(FMT)}")
                        client_send_socket.send(header + lookup)
                        res_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
                        if res_type not in [
                            HeaderCode.REQUEST_UNAME.value,
                            HeaderCode.ERROR.value,
                        ]:
                            raise RequestException(
                                msg="Invalid message type in header",
                                code=ExceptionCode.INVALID_HEADER,
                            )
                        else:
                            response_length = int(
                                client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip()
                            )
                            response = client_send_socket.recv(response_length)
                            if res_type == HeaderCode.REQUEST_UNAME.value:
                                username = response.decode(FMT)
                                print(f"\nUser {username} is trying to send a message")
                                peers[peer_addr[0]] = username
                            else:
                                exception = msgpack.unpackb(
                                    response,
                                    object_hook=RequestException.from_dict,
                                    raw=False,
                                )
                                logging.error(msg=exception)
                                raise exception
                    except RequestException as e:
                        logging.error(msg=e)
                        break
                else:
                    try:
                        message_content: str = self.receive_msg(notified_socket)
                        username = peers[notified_socket.getpeername()[0]]
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


class Ui_DrizzleMainWindow(QWidget):
    global client_send_socket
    global client_recv_socket
    global uname_to_status

    def __init__(self, MainWindow):
        super(Ui_DrizzleMainWindow, self).__init__()
        try:
            self.user_settings = MainWindow.user_settings
            SERVER_IP = self.user_settings["server_ip"]
            SERVER_ADDR = (SERVER_IP, SERVER_RECV_PORT)
            client_send_socket.connect(SERVER_ADDR)
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
        global selected_uname

        if self.txtedit_MessageInput.toPlainText() == "":
            return
        peer_ip = request_ip(selected_uname, client_send_socket)
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

    def on_file_item_selected(self, item: QTreeWidgetItem, column: int):
        global selected_file_item
        data: DirData = item.data(column, Qt.UserRole)
        selected_file_item = data
        self.lbl_FileInfo.setText(data["name"])

    def show_file_info_dialog(self, MainWindow):
        global selected_file_item
        size = selected_file_item["size"]
        item_info = {
            "name": selected_file_item["name"],
            "hash": selected_file_item["hash"] or "Not available",
            "type": selected_file_item["type"],
            "size": convert_size(size or 0),
        }
        if selected_file_item["type"] != "file":
            size, count = get_directory_size(selected_file_item, 0, 0)
            item_info["size"] = convert_size(size)
            item_info["count"] = f"{count} files"
        message_box = QMessageBox(MainWindow)
        message_box.setIcon(QMessageBox.Information)
        message_box.setWindowTitle("File Info")
        message_box.setText(selected_file_item["name"])
        message_box.setInformativeText(json.dumps(item_info, indent=4, sort_keys=True))
        message_box.addButton(QMessageBox.Close)
        message_box.exec()

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
            client_send_socket.send(search_header + searchquery_bytes)
            response_header_type = client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
            if response_header_type == HeaderCode.FILE_SEARCH.value:
                response_len = int(client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
                browse_files: list[DBData] = msgpack.unpackb(
                    recvall(client_send_socket, response_len),
                )
                if len(browse_files):
                    self.file_tree.clear()
                    self.file_tree.headerItem().setText(0, username)
                    self.render_file_tree(browse_files[0]["share"], self.file_tree)
                else:
                    print("No files found")
            else:
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
        self.file_tree.itemClicked.connect(self.on_file_item_selected)
        self.file_tree.header().setVisible(True)
        self.file_tree.headerItem().setText(0, "No user selected")

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
        self.btn_FileInfo.clicked.connect(lambda: self.show_file_info_dialog(MainWindow))

        self.horizontalLayout_2.addWidget(self.btn_FileInfo)

        self.btn_FileDownload = QPushButton(self.centralwidget)
        self.btn_FileDownload.setObjectName("pushButton_4")
        self.btn_FileDownload.setEnabled(True)

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

        self.scrollArea = QScrollArea(self.centralwidget)
        self.scrollArea.setObjectName("scrollArea")
        sizePolicy5 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        sizePolicy5.setHorizontalStretch(0)
        sizePolicy5.setVerticalStretch(0)
        sizePolicy5.setHeightForWidth(self.scrollArea.sizePolicy().hasHeightForWidth())
        self.scrollArea.setSizePolicy(sizePolicy5)
        self.scrollArea.setMaximumSize(QSize(16777215, 150))
        self.scrollArea.setWidgetResizable(True)
        self.scrollAreaWidgetContents = QWidget()
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.scrollAreaWidgetContents.setGeometry(QRect(0, 0, 831, 328))
        self.verticalLayout_5 = QVBoxLayout(self.scrollAreaWidgetContents)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.widget_6 = QWidget(self.scrollAreaWidgetContents)
        self.widget_6.setObjectName("widget_6")
        sizePolicy6 = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        sizePolicy6.setHorizontalStretch(0)
        sizePolicy6.setVerticalStretch(0)
        sizePolicy6.setHeightForWidth(self.widget_6.sizePolicy().hasHeightForWidth())
        self.widget_6.setSizePolicy(sizePolicy6)
        self.widget_6.setMinimumSize(QSize(0, 40))
        self.widget_6.setMaximumSize(QSize(16777215, 40))
        self.horizontalLayout_8 = QHBoxLayout(self.widget_6)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.label_10 = QLabel(self.widget_6)
        self.label_10.setObjectName("label_10")

        self.horizontalLayout_8.addWidget(self.label_10)

        self.progressBar_6 = QProgressBar(self.widget_6)
        self.progressBar_6.setObjectName("progressBar_6")
        self.progressBar_6.setValue(24)

        self.horizontalLayout_8.addWidget(self.progressBar_6)

        self.verticalLayout_5.addWidget(self.widget_6)

        self.widget_3 = QWidget(self.scrollAreaWidgetContents)
        self.widget_3.setObjectName("widget_3")
        sizePolicy6.setHeightForWidth(self.widget_3.sizePolicy().hasHeightForWidth())
        self.widget_3.setSizePolicy(sizePolicy6)
        self.widget_3.setMinimumSize(QSize(0, 40))
        self.widget_3.setMaximumSize(QSize(16777215, 40))
        self.horizontalLayout_5 = QHBoxLayout(self.widget_3)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.label_7 = QLabel(self.widget_3)
        self.label_7.setObjectName("label_7")

        self.horizontalLayout_5.addWidget(self.label_7)

        self.progressBar_3 = QProgressBar(self.widget_3)
        self.progressBar_3.setObjectName("progressBar_3")
        self.progressBar_3.setValue(24)

        self.horizontalLayout_5.addWidget(self.progressBar_3)

        self.verticalLayout_5.addWidget(self.widget_3)

        self.widget_4 = QWidget(self.scrollAreaWidgetContents)
        self.widget_4.setObjectName("widget_4")
        sizePolicy6.setHeightForWidth(self.widget_4.sizePolicy().hasHeightForWidth())
        self.widget_4.setSizePolicy(sizePolicy6)
        self.widget_4.setMinimumSize(QSize(0, 40))
        self.widget_4.setMaximumSize(QSize(16777215, 40))
        self.horizontalLayout_6 = QHBoxLayout(self.widget_4)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.label_8 = QLabel(self.widget_4)
        self.label_8.setObjectName("label_8")

        self.horizontalLayout_6.addWidget(self.label_8)

        self.progressBar_4 = QProgressBar(self.widget_4)
        self.progressBar_4.setObjectName("progressBar_4")
        self.progressBar_4.setValue(24)

        self.horizontalLayout_6.addWidget(self.progressBar_4)

        self.verticalLayout_5.addWidget(self.widget_4)

        self.widget = QWidget(self.scrollAreaWidgetContents)
        self.widget.setObjectName("widget")
        sizePolicy6.setHeightForWidth(self.widget.sizePolicy().hasHeightForWidth())
        self.widget.setSizePolicy(sizePolicy6)
        self.widget.setMinimumSize(QSize(0, 40))
        self.widget.setMaximumSize(QSize(16777215, 40))
        self.horizontalLayout_3 = QHBoxLayout(self.widget)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_5 = QLabel(self.widget)
        self.label_5.setObjectName("label_5")

        self.horizontalLayout_3.addWidget(self.label_5)

        self.progressBar = QProgressBar(self.widget)
        self.progressBar.setObjectName("progressBar")
        self.progressBar.setValue(24)

        self.horizontalLayout_3.addWidget(self.progressBar)

        self.verticalLayout_5.addWidget(self.widget, 0, Qt.AlignTop)

        self.widget_5 = QWidget(self.scrollAreaWidgetContents)
        self.widget_5.setObjectName("widget_5")
        sizePolicy6.setHeightForWidth(self.widget_5.sizePolicy().hasHeightForWidth())
        self.widget_5.setSizePolicy(sizePolicy6)
        self.widget_5.setMinimumSize(QSize(0, 40))
        self.widget_5.setMaximumSize(QSize(16777215, 40))
        self.horizontalLayout_7 = QHBoxLayout(self.widget_5)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.label_9 = QLabel(self.widget_5)
        self.label_9.setObjectName("label_9")

        self.horizontalLayout_7.addWidget(self.label_9)

        self.progressBar_5 = QProgressBar(self.widget_5)
        self.progressBar_5.setObjectName("progressBar_5")
        self.progressBar_5.setValue(24)

        self.horizontalLayout_7.addWidget(self.progressBar_5)

        self.verticalLayout_5.addWidget(self.widget_5)

        self.widget_2 = QWidget(self.scrollAreaWidgetContents)
        self.widget_2.setObjectName("widget_2")
        sizePolicy6.setHeightForWidth(self.widget_2.sizePolicy().hasHeightForWidth())
        self.widget_2.setSizePolicy(sizePolicy6)
        self.widget_2.setMinimumSize(QSize(0, 40))
        self.widget_2.setMaximumSize(QSize(16777215, 40))
        self.horizontalLayout_4 = QHBoxLayout(self.widget_2)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.label_6 = QLabel(self.widget_2)
        self.label_6.setObjectName("label_6")

        self.horizontalLayout_4.addWidget(self.label_6)

        self.progressBar_2 = QProgressBar(self.widget_2)
        self.progressBar_2.setObjectName("progressBar_2")
        self.progressBar_2.setValue(24)

        self.horizontalLayout_4.addWidget(self.progressBar_2)

        self.verticalLayout_5.addWidget(self.widget_2)

        self.widget_7 = QWidget(self.scrollAreaWidgetContents)
        self.widget_7.setObjectName("widget_7")
        sizePolicy6.setHeightForWidth(self.widget_7.sizePolicy().hasHeightForWidth())
        self.widget_7.setSizePolicy(sizePolicy6)
        self.widget_7.setMinimumSize(QSize(0, 40))
        self.widget_7.setMaximumSize(QSize(16777215, 40))
        self.horizontalLayout_9 = QHBoxLayout(self.widget_7)
        self.horizontalLayout_9.setObjectName("horizontalLayout_9")
        self.label_11 = QLabel(self.widget_7)
        self.label_11.setObjectName("label_11")

        self.horizontalLayout_9.addWidget(self.label_11)

        self.progressBar_7 = QProgressBar(self.widget_7)
        self.progressBar_7.setObjectName("progressBar_7")
        self.progressBar_7.setValue(24)

        self.horizontalLayout_9.addWidget(self.progressBar_7)

        self.verticalLayout_5.addWidget(self.widget_7, 0, Qt.AlignTop)

        self.scrollArea.setWidget(self.scrollAreaWidgetContents)

        self.verticalLayout.addWidget(self.scrollArea)

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
        self.label_10.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_7.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_8.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_5.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_9.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_6.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_11.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))

    def open_settings(self, MainWindow):
        settings_dialog = QDialog(MainWindow)
        settings_dialog.ui = Ui_SettingsDialog(settings_dialog, self.user_settings)
        settings_dialog.exec()

    def import_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "Import Files", str(Path.home()), "All Files (*)"
        )
        for file in files:
            imported = import_file_to_share(
                Path(file), Path(self.user_settings["share_folder_path"])
            )
            if imported is not None:
                print(f"Imported file {imported}")
        update_share_data(Path(self.user_settings["share_folder_path"]), client_send_socket)

    def import_folder(self):
        dir = QFileDialog.getExistingDirectory(
            self, "Import Folder", str(Path.home()), QFileDialog.ShowDirsOnly
        )
        imported = import_file_to_share(Path(dir), Path(self.user_settings["share_folder_path"]))
        if imported is not None:
            print(f"Imported file {imported}")
        update_share_data(Path(self.user_settings["share_folder_path"]), client_send_socket)
