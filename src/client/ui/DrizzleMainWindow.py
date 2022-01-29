import logging
import socket
import sys
import time
from pathlib import Path

import msgpack
from PyQt5.QtCore import *
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import *

sys.path.append("../")
from utils.constants import (
    CLIENT_RECV_PORT,
    CLIENT_SEND_PORT,
    FMT,
    HEADER_MSG_LEN,
    HEADER_TYPE_LEN,
    HEARTBEAT_TIMER,
    ONLINE_TIMEOUT,
    SERVER_RECV_PORT,
)
from utils.exceptions import ExceptionCode, RequestException
from utils.helpers import path_to_dict
from utils.socket_functions import get_ip, recvall
from utils.types import DBData, DirData, HeaderCode

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

uname_to_status: dict[str, int] = {}


class HeartbeatWorker(QObject):
    update_status = pyqtSignal(dict)

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
                raise RequestException(
                    f"Server sent invalid message type in header: {type}",
                    ExceptionCode.INVALID_HEADER,
                )


class Ui_DrizzleMainWindow(QWidget):
    global client_send_socket
    global client_recv_socket
    global uname_to_status

    def __init__(self, MainWindow):
        super(Ui_DrizzleMainWindow, self).__init__()
        try:
            SERVER_IP = MainWindow.user_settings["server_ip"]
            SERVER_ADDR = (SERVER_IP, SERVER_RECV_PORT)
            client_send_socket.connect(SERVER_ADDR)
            username = MainWindow.user_settings["uname"].encode(FMT)
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
                else:
                    logging.fatal(msg=exception.msg)
                    print("\nSorry something went wrong")
                    client_send_socket.close()
                    client_recv_socket.close()
                    MainWindow.close()
            share_data = msgpack.packb(
                path_to_dict(Path(MainWindow.user_settings["share_folder_path"]))["children"]
            )
            share_data_header = (
                f"{HeaderCode.SHARE_DATA.value}{len(share_data):<{HEADER_MSG_LEN}}".encode(FMT)
            )
            client_send_socket.sendall(share_data_header + share_data)

            self.heartbeat_thread = QThread()
            self.heartbeat_worker = HeartbeatWorker()
            self.heartbeat_worker.moveToThread(self.heartbeat_thread)
            self.heartbeat_thread.started.connect(self.heartbeat_worker.run)
            self.heartbeat_worker.update_status.connect(self.update_online_status)
            self.heartbeat_thread.start()

        except Exception as e:
            logging.error(f"Could not connect to server: {e}")
        self.setupUi(MainWindow)

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
            else:
                dir_item = QTreeWidgetItem(parent)
                dir_item.setText(0, item["name"] + "/")
                self.render_file_tree(item["children"], dir_item)

    def update_online_status(self, new_status: dict[str, int]):
        global uname_to_status
        old_users = set(uname_to_status.keys())
        new_users = set(new_status.keys())
        to_add = new_users.difference(old_users)
        users_to_remove = old_users.difference(new_users)

        for index in range(self.lw_OnlineStatus.count()):
            item = self.lw_OnlineStatus.item(index)
            username = item.data(Qt.UserRole)  # type: ignore
            logging.debug(username)
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
        items = self.lw_OnlineStatus.selectedItems()
        if len(items):
            item = items[0]
            username: str = item.data(Qt.UserRole)
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
                logging.error("Error occured while searching for files")

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

        self.pushButton_2 = QPushButton(self.centralwidget)
        self.pushButton_2.setObjectName("pushButton_2")

        self.Buttons.addWidget(self.pushButton_2)

        self.pushButton = QPushButton(self.centralwidget)
        self.pushButton.setObjectName("pushButton")

        self.Buttons.addWidget(self.pushButton)

        self.verticalLayout.addLayout(self.Buttons)

        self.Content = QHBoxLayout()
        self.Content.setObjectName("Content")
        self.Files = QVBoxLayout()
        self.Files.setObjectName("Files")
        self.label = QLabel(self.centralwidget)
        self.label.setObjectName("label")

        self.Files.addWidget(self.label)

        self.file_tree = QTreeWidget(self.centralwidget)
        # QTreeWidgetItem(self.file_tree)
        # __qtreewidgetitem = QTreeWidgetItem(self.file_tree)
        # QTreeWidgetItem(__qtreewidgetitem)
        # QTreeWidgetItem(__qtreewidgetitem)
        # QTreeWidgetItem(__qtreewidgetitem)
        # QTreeWidgetItem(self.file_tree)
        # __qtreewidgetitem1 = QTreeWidgetItem(self.file_tree)
        # QTreeWidgetItem(__qtreewidgetitem1)
        # QTreeWidgetItem(__qtreewidgetitem1)
        # QTreeWidgetItem(__qtreewidgetitem1)
        # QTreeWidgetItem(__qtreewidgetitem1)
        # QTreeWidgetItem(self.file_tree)
        # self.file_tree.setObjectName("treeWidget")
        self.file_tree.header().setVisible(True)
        self.file_tree.headerItem().setText(0, "No user selected")

        self.Files.addWidget(self.file_tree)

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_4 = QLabel(self.centralwidget)
        self.label_4.setObjectName("label_4")

        self.horizontalLayout_2.addWidget(self.label_4)

        self.horizontalSpacer_2 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer_2)

        self.pushButton_5 = QPushButton(self.centralwidget)
        self.pushButton_5.setObjectName("pushButton_5")
        self.pushButton_5.setEnabled(True)

        self.horizontalLayout_2.addWidget(self.pushButton_5)

        self.pushButton_4 = QPushButton(self.centralwidget)
        self.pushButton_4.setObjectName("pushButton_4")
        self.pushButton_4.setEnabled(True)

        self.horizontalLayout_2.addWidget(self.pushButton_4)

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

        self.textEdit = QTextEdit(self.centralwidget)
        self.textEdit.setObjectName("textEdit")
        sizePolicy2 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        sizePolicy2.setHorizontalStretch(0)
        sizePolicy2.setVerticalStretch(5)
        sizePolicy2.setHeightForWidth(self.textEdit.sizePolicy().hasHeightForWidth())
        self.textEdit.setSizePolicy(sizePolicy2)
        self.textEdit.setMinimumSize(QSize(0, 0))
        self.textEdit.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.Users.addWidget(self.textEdit)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.horizontalLayout.setSizeConstraint(QLayout.SetDefaultConstraint)
        self.plainTextEdit = QPlainTextEdit(self.centralwidget)
        self.plainTextEdit.setObjectName("plainTextEdit")
        self.plainTextEdit.setEnabled(True)
        sizePolicy3 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        sizePolicy3.setHorizontalStretch(0)
        sizePolicy3.setVerticalStretch(0)
        sizePolicy3.setHeightForWidth(self.plainTextEdit.sizePolicy().hasHeightForWidth())
        self.plainTextEdit.setSizePolicy(sizePolicy3)
        self.plainTextEdit.setMaximumSize(QSize(16777215, 80))

        self.horizontalLayout.addWidget(self.plainTextEdit)

        self.verticalLayout_6 = QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.pushButton_3 = QPushButton(self.centralwidget)
        self.pushButton_3.setObjectName("pushButton_3")
        sizePolicy4 = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        sizePolicy4.setHorizontalStretch(0)
        sizePolicy4.setVerticalStretch(0)
        sizePolicy4.setHeightForWidth(self.pushButton_3.sizePolicy().hasHeightForWidth())
        self.pushButton_3.setSizePolicy(sizePolicy4)

        self.verticalLayout_6.addWidget(self.pushButton_3)

        self.pushButton_6 = QPushButton(self.centralwidget)
        self.pushButton_6.setObjectName("pushButton_6")
        sizePolicy4.setHeightForWidth(self.pushButton_6.sizePolicy().hasHeightForWidth())
        self.pushButton_6.setSizePolicy(sizePolicy4)

        self.verticalLayout_6.addWidget(self.pushButton_6)

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
                "MainWindow", f"Drizzle / {MainWindow.user_settings['uname']}", None
            )
        )
        self.pushButton_2.setText(QCoreApplication.translate("MainWindow", "Add Files", None))
        self.pushButton.setText(QCoreApplication.translate("MainWindow", "Settings", None))
        self.label.setText(QCoreApplication.translate("MainWindow", "Browse Files", None))
        # ___qtreewidgetitem = self.file_tree.headerItem()
        # ___qtreewidgetitem.setText(
        #     0, QCoreApplication.translate("MainWindow", "RichardRoe12", None)
        # )

        __sortingEnabled = self.file_tree.isSortingEnabled()
        # self.file_tree.setSortingEnabled(False)
        # ___qtreewidgetitem1 = self.file_tree.topLevelItem(0)
        # ___qtreewidgetitem1.setText(
        #     0, QCoreApplication.translate("MainWindow", "photoshop.iso", None)
        # )
        # ___qtreewidgetitem2 = self.file_tree.topLevelItem(1)
        # ___qtreewidgetitem2.setText(0, QCoreApplication.translate("MainWindow", "Movies/", None))
        # ___qtreewidgetitem3 = ___qtreewidgetitem2.child(0)
        # ___qtreewidgetitem3.setText(
        #     0, QCoreApplication.translate("MainWindow", "The Matrix.mov", None)
        # )
        # ___qtreewidgetitem4 = ___qtreewidgetitem2.child(1)
        # ___qtreewidgetitem4.setText(
        #     0, QCoreApplication.translate("MainWindow", "Forrest Gump.mp4", None)
        # )
        # ___qtreewidgetitem5 = ___qtreewidgetitem2.child(2)
        # ___qtreewidgetitem5.setText(0, QCoreApplication.translate("MainWindow", "Django.mp4", None))
        # ___qtreewidgetitem6 = self.file_tree.topLevelItem(2)
        # ___qtreewidgetitem6.setText(
        #     0, QCoreApplication.translate("MainWindow", "msoffice.zip", None)
        # )
        # ___qtreewidgetitem7 = self.file_tree.topLevelItem(3)
        # ___qtreewidgetitem7.setText(0, QCoreApplication.translate("MainWindow", "Games/", None))
        # ___qtreewidgetitem8 = ___qtreewidgetitem7.child(0)
        # ___qtreewidgetitem8.setText(0, QCoreApplication.translate("MainWindow", "NFS/", None))
        # ___qtreewidgetitem9 = ___qtreewidgetitem7.child(1)
        # ___qtreewidgetitem9.setText(
        #     0, QCoreApplication.translate("MainWindow", "nfsmostwanted.zip", None)
        # )
        # ___qtreewidgetitem10 = ___qtreewidgetitem7.child(2)
        # ___qtreewidgetitem10.setText(
        #     0, QCoreApplication.translate("MainWindow", "TLauncher.zip", None)
        # )
        # ___qtreewidgetitem11 = ___qtreewidgetitem7.child(3)
        # ___qtreewidgetitem11.setText(0, QCoreApplication.translate("MainWindow", "GTA-V.iso", None))
        # ___qtreewidgetitem12 = self.file_tree.topLevelItem(4)
        # ___qtreewidgetitem12.setText(
        #     0, QCoreApplication.translate("MainWindow", "Study Material/", None)
        # )
        self.file_tree.setSortingEnabled(__sortingEnabled)

        self.label_4.setText(
            QCoreApplication.translate("MainWindow", "Selected File/Folder: msoffice.zip", None)
        )
        self.pushButton_5.setText(QCoreApplication.translate("MainWindow", "Info", None))
        self.pushButton_4.setText(QCoreApplication.translate("MainWindow", "Download", None))
        self.label_2.setText(QCoreApplication.translate("MainWindow", "Users", None))

        __sortingEnabled1 = self.lw_OnlineStatus.isSortingEnabled()
        self.lw_OnlineStatus.setSortingEnabled(False)
        # ___qlistwidgetitem = self.lw_OnlineStatus.item(0)
        # ___qlistwidgetitem.setText(QCoreApplication.translate("MainWindow", "RichardRoe12", None))
        # ___qlistwidgetitem1 = self.lw_OnlineStatus.item(1)
        # ___qlistwidgetitem1.setText(QCoreApplication.translate("MainWindow", "ronaldw", None))
        # ___qlistwidgetitem2 = self.lw_OnlineStatus.item(2)
        # ___qlistwidgetitem2.setText(
        #     QCoreApplication.translate("MainWindow", "harrypotter (last active: 11:45 am)", None)
        # )
        # ___qlistwidgetitem3 = self.lw_OnlineStatus.item(3)
        # ___qlistwidgetitem3.setText(QCoreApplication.translate("MainWindow", "anonymous_lol", None))
        self.lw_OnlineStatus.setSortingEnabled(__sortingEnabled1)

        self.textEdit.setHtml(
            QCoreApplication.translate(
                "MainWindow",
                '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n'
                '<html><head><meta name="qrichtext" content="1" /><style type="text/css">\n'
                "p, li { white-space: pre-wrap; }\n"
                "</style></head><body style=\" font-family:'Noto Sans'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
                '<p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600; color:#e5a50a;">12:03</span><span style=" font-weight:600;"> RichardRoe12: </span>Hello</p>\n'
                '<p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600; color:#1a5fb4;">12:03</span><span style=" font-weight:600;"> You: </span>Hii</p>\n'
                '<p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600; color:#e5a50a;">12:03</span><span style="'
                ' font-weight:600;"> RichardRoe12: </span>Got any games?</p>\n'
                '<p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600; color:#1a5fb4;">12:03</span><span style=" font-weight:600;"> You: </span>Probably</p>\n'
                '<p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-weight:600; color:#1a5fb4;">12:03</span><span style=" font-weight:600;"> You: </span>Wait ill upload something...</p>',
                "</body></html>",
                # None,
            )
        )
        self.plainTextEdit.setPlaceholderText(
            QCoreApplication.translate("MainWindow", "Enter message", None)
        )
        self.pushButton_3.setText(QCoreApplication.translate("MainWindow", "Send Message", None))
        self.pushButton_6.setText(QCoreApplication.translate("MainWindow", "Send File", None))
        self.label_12.setText(QCoreApplication.translate("MainWindow", "Downloading:", None))
        self.label_10.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_7.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_8.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_5.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_9.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_6.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))
        self.label_11.setText(QCoreApplication.translate("MainWindow", "TextLabel", None))

    # retranslateUi
