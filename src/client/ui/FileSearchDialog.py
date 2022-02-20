# Imports (standard libraries)
import logging
import socket
import sys
from pprint import pformat

# Imports (PyPI)
import msgpack
from PyQt5.QtCore import QCoreApplication, QMetaObject, QMutex, Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

# Imports (utilities)
sys.path.append("../")
from utils.constants import FMT, HEADER_MSG_LEN, HEADER_TYPE_LEN
from utils.exceptions import RequestException
from utils.helpers import convert_size
from utils.socket_functions import recvall
from utils.types import HeaderCode, ItemSearchResult

# The selected file item in the search results
selected_item: ItemSearchResult = {}


class Ui_FileSearchDialog(QDialog):
    """A dialog that displays search results and allows the user to download files

    Attributes
    ----------
    Dialog
        The dialog object
    client_send_socket : socket.socket
        The socket that connects to the server
    mutex : QMutex
        A mutex that protects the send socket from race conditions
    start_download : pyqtSignal
        A signal that is emitted when the download button is pressed

    Methods
    ----------
    search(mutex: QMutex)
        Sends the search query to the server
    on_selection_changed()
        Updates the selected item when the user selects an item from the search results
    download(Dialog)
        Emits the start_download signal and closes the dialog
    """

    def __init__(self, Dialog, client_send_socket: socket.socket, mutex: QMutex, start_download: pyqtSignal) -> None:
        super().__init__()
        self.setupUi(Dialog, mutex)
        self.client_send_socket = client_send_socket
        self.start_download = start_download

    def setupUi(self, Dialog, mutex: QMutex) -> None:
        global selected_item

        if not Dialog.objectName():
            Dialog.setObjectName("FileSearchDialog")
        Dialog.resize(582, 480)
        self.verticalLayout_2 = QVBoxLayout(Dialog)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QLabel(Dialog)
        self.label.setObjectName("label")

        self.verticalLayout.addWidget(self.label)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.lineEdit = QLineEdit(Dialog)
        self.lineEdit.setObjectName("lineEdit")

        self.horizontalLayout.addWidget(self.lineEdit)

        self.btn_Search = QPushButton(Dialog)
        self.btn_Search.setObjectName("pushButton")
        self.btn_Search.clicked.connect(lambda: self.search(mutex))  # type: ignore

        self.horizontalLayout.addWidget(self.btn_Search)

        self.verticalLayout.addLayout(self.horizontalLayout)

        self.tableWidget = QTableWidget(Dialog)
        if self.tableWidget.columnCount() < 4:
            self.tableWidget.setColumnCount(4)
        __qtablewidgetitem = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        __qtablewidgetitem3 = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(3, __qtablewidgetitem3)

        self.tableWidget.setObjectName("tableWidget")
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tableWidget.sizePolicy().hasHeightForWidth())
        self.tableWidget.setSizePolicy(sizePolicy)
        self.tableWidget.setLayoutDirection(Qt.LeftToRight)  # type: ignore
        self.tableWidget.setFrameShape(QFrame.StyledPanel)
        self.tableWidget.setShowGrid(True)
        self.tableWidget.setGridStyle(Qt.SolidLine)  # type: ignore
        self.tableWidget.setSortingEnabled(False)
        self.tableWidget.setWordWrap(True)
        self.tableWidget.setCornerButtonEnabled(True)
        self.tableWidget.horizontalHeader().setVisible(True)
        self.tableWidget.horizontalHeader().setCascadingSectionResizes(False)
        self.tableWidget.horizontalHeader().setDefaultSectionSize(150)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.verticalHeader().setStretchLastSection(False)
        self.tableWidget.setEditTriggers(QTableView.NoEditTriggers)

        self.tableWidget.itemSelectionChanged.connect(self.on_selection_changed)  # type: ignore

        self.verticalLayout.addWidget(self.tableWidget)

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer)

        self.btn_Download = QPushButton(Dialog)
        self.btn_Download.setObjectName("pushButton_2")
        self.btn_Download.clicked.connect(lambda: self.download(Dialog))  # type: ignore

        self.horizontalLayout_2.addWidget(self.btn_Download)

        self.verticalLayout.addLayout(self.horizontalLayout_2)

        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.retranslateUi(Dialog)

        QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog) -> None:
        Dialog.setWindowTitle(QCoreApplication.translate("FileSearchDialog", "File Search Dialog", None))
        self.label.setText(QCoreApplication.translate("FileSearchDialog", "Search your network for files", None))
        self.btn_Search.setText(QCoreApplication.translate("FileSearchDialog", "Search", None))
        ___qtablewidgetitem = self.tableWidget.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(QCoreApplication.translate("FileSearchDialog", "Item", None))
        ___qtablewidgetitem1 = self.tableWidget.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("FileSearchDialog", "Type", None))
        ___qtablewidgetitem2 = self.tableWidget.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(QCoreApplication.translate("FileSearchDialog", "Owner", None))
        ___qtablewidgetitem3 = self.tableWidget.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(QCoreApplication.translate("FileSearchDialog", "Size", None))

        __sortingEnabled = self.tableWidget.isSortingEnabled()
        self.tableWidget.setSortingEnabled(False)

        self.tableWidget.setSortingEnabled(__sortingEnabled)

        header = self.tableWidget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)

        self.tableWidget.setSelectionBehavior(QTableView.SelectRows)
        self.tableWidget.setSelectionMode(QTableView.SingleSelection)

        self.btn_Download.setText(QCoreApplication.translate("FileSearchDialog", "Download", None))

    def search(self, mutex: QMutex) -> None:
        """Sends the search query to the server

        Attributes
        ----------
        mutex : QMutex
            The mutex that protects the socket from race conditions
        """

        # Ignore empty search queries
        if not self.lineEdit.text().strip():
            return

        try:
            # Clear the existing search results
            self.tableWidget.clearContents()

            # Encode and send the query to the server
            search_query = self.lineEdit.text()
            search_query_bytes = search_query.encode(FMT)
            search_query_header = f"{HeaderCode.FILE_SEARCH.value}{len(search_query_bytes):<{HEADER_MSG_LEN}}".encode(
                FMT
            )
            mutex.lock()
            self.client_send_socket.send(search_query_header + search_query_bytes)

            res_header = self.client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
            res_len = int(self.client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())

            # Server returned the search results
            if res_header == HeaderCode.FILE_SEARCH.value:
                res_data: list[ItemSearchResult] = msgpack.unpackb(recvall(self.client_send_socket, res_len))
                mutex.unlock()
                logging.debug(f"{pformat(res_data)}")
                self.tableWidget.setRowCount(len(res_data))

                # Render the search results
                for index, item in enumerate(res_data):
                    twItem_SearchItemName = QTableWidgetItem()
                    twItem_SearchItemName.setData(1, item)
                    twItem_SearchItemName.setText(item["data"]["name"])
                    twItem_SearchItemName.setToolTip(item["data"]["path"])
                    twItem_SearchItemType = QTableWidgetItem()
                    twItem_SearchItemType.setText(item["data"]["type"])
                    twItem_SearchItemOwner = QTableWidgetItem()
                    twItem_SearchItemOwner.setText(item["owner"])
                    twItem_SearchItemSize = QTableWidgetItem()
                    twItem_SearchItemSize.setText(convert_size(item["data"]["size"]) if item["data"]["size"] else "NA")
                    self.tableWidget.setItem(index, 0, twItem_SearchItemName)
                    self.tableWidget.setItem(index, 1, twItem_SearchItemType)
                    self.tableWidget.setItem(index, 2, twItem_SearchItemOwner)
                    self.tableWidget.setItem(index, 3, twItem_SearchItemSize)
            elif res_header == HeaderCode.ERROR.value:
                err = msgpack.unpackb(
                    self.client_send_socket.recv(res_len),
                    object_hook=RequestException.from_dict,
                    raw=False,
                )
                mutex.unlock()
                logging.error(f"Could not search files: {err.msg}")
            else:
                logging.error("invalid header type in search response")
                mutex.unlock()
        except Exception as e:
            logging.exception(f"Error while searching files: {e}")
        return

    def on_selection_changed(self) -> None:
        """Updates the selected item when the user selects an item from the search results"""

        global selected_item
        if len(self.tableWidget.selectedItems()):
            selected_item = self.tableWidget.selectedItems()[0].data(1)
            logging.debug(selected_item)

    def download(self, Dialog) -> None:
        """Emits the start_download signal and closes the dialog"""

        self.start_download.emit(selected_item)  # type: ignore
        Dialog.close()
