import logging
import socket
import sys
from pprint import pprint

import msgpack
from PyQt5.QtCore import QCoreApplication, QMetaObject, Qt
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

sys.path.append("../")
from utils.constants import FMT, HEADER_MSG_LEN, HEADER_TYPE_LEN
from utils.exceptions import RequestException
from utils.helpers import convert_size
from utils.socket_functions import recvall
from utils.types import HeaderCode, ItemSearchResult

selected_item: ItemSearchResult = {}


class Ui_FileSearchDialog(QDialog):
    def __init__(self, Dialog, client_send_socket: socket.socket, mutex, start_download) -> None:
        super().__init__()
        self.setupUi(Dialog, mutex)
        self.client_send_socket = client_send_socket
        self.start_download = start_download

    def setupUi(self, Dialog, mutex):
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
        self.btn_Search.clicked.connect(lambda: self.search(mutex))

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
        # if self.tableWidget.rowCount() < 3:
        #     self.tableWidget.setRowCount(3)
        # __qtablewidgetitem4 = QTableWidgetItem()
        # self.tableWidget.setVerticalHeaderItem(1, __qtablewidgetitem4)
        # __qtablewidgetitem5 = QTableWidgetItem()
        # self.tableWidget.setVerticalHeaderItem(2, __qtablewidgetitem5)
        # __qtablewidgetitem6 = QTableWidgetItem()
        # self.tableWidget.setItem(0, 0, __qtablewidgetitem6)
        # __qtablewidgetitem7 = QTableWidgetItem()
        # self.tableWidget.setItem(0, 1, __qtablewidgetitem7)
        # __qtablewidgetitem8 = QTableWidgetItem()
        # self.tableWidget.setItem(0, 2, __qtablewidgetitem8)
        # __qtablewidgetitem9 = QTableWidgetItem()
        # self.tableWidget.setItem(1, 0, __qtablewidgetitem9)
        # __qtablewidgetitem10 = QTableWidgetItem()
        # self.tableWidget.setItem(1, 1, __qtablewidgetitem10)
        # __qtablewidgetitem11 = QTableWidgetItem()
        # self.tableWidget.setItem(1, 2, __qtablewidgetitem11)
        # __qtablewidgetitem12 = QTableWidgetItem()
        # self.tableWidget.setItem(2, 0, __qtablewidgetitem12)
        # __qtablewidgetitem13 = QTableWidgetItem()
        # self.tableWidget.setItem(2, 1, __qtablewidgetitem13)
        # __qtablewidgetitem14 = QTableWidgetItem()
        # self.tableWidget.setItem(2, 2, __qtablewidgetitem14)
        self.tableWidget.setObjectName("tableWidget")
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tableWidget.sizePolicy().hasHeightForWidth())
        self.tableWidget.setSizePolicy(sizePolicy)
        self.tableWidget.setLayoutDirection(Qt.LeftToRight)
        self.tableWidget.setFrameShape(QFrame.StyledPanel)
        self.tableWidget.setShowGrid(True)
        self.tableWidget.setGridStyle(Qt.SolidLine)
        self.tableWidget.setSortingEnabled(False)
        self.tableWidget.setWordWrap(True)
        self.tableWidget.setCornerButtonEnabled(True)
        self.tableWidget.horizontalHeader().setVisible(True)
        self.tableWidget.horizontalHeader().setCascadingSectionResizes(False)
        self.tableWidget.horizontalHeader().setDefaultSectionSize(150)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.verticalHeader().setStretchLastSection(False)
        self.tableWidget.setEditTriggers(QTableView.NoEditTriggers)

        self.tableWidget.itemSelectionChanged.connect(self.on_selection_changed)

        self.verticalLayout.addWidget(self.tableWidget)

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer)

        self.btn_Download = QPushButton(Dialog)
        self.btn_Download.setObjectName("pushButton_2")
        self.btn_Download.clicked.connect(lambda: self.download(Dialog))

        self.horizontalLayout_2.addWidget(self.btn_Download)

        self.verticalLayout.addLayout(self.horizontalLayout_2)

        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.retranslateUi(Dialog)

        QMetaObject.connectSlotsByName(Dialog)

    # setupUi

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(
            QCoreApplication.translate("FileSearchDialog", "File Search Dialog", None)
        )
        self.label.setText(
            QCoreApplication.translate("FileSearchDialog", "Search your network for files", None)
        )
        self.btn_Search.setText(QCoreApplication.translate("FileSearchDialog", "Search", None))
        ___qtablewidgetitem = self.tableWidget.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(QCoreApplication.translate("FileSearchDialog", "Item", None))
        ___qtablewidgetitem1 = self.tableWidget.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("FileSearchDialog", "Type", None))
        ___qtablewidgetitem2 = self.tableWidget.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(QCoreApplication.translate("FileSearchDialog", "Owner", None))
        ___qtablewidgetitem3 = self.tableWidget.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(QCoreApplication.translate("FileSearchDialog", "Size", None))
        # ___qtablewidgetitem3 = self.tableWidget.verticalHeaderItem(0)
        # ___qtablewidgetitem3.setText(QCoreApplication.translate("FileSearchDialog", "1", None))
        # ___qtablewidgetitem4 = self.tableWidget.verticalHeaderItem(1)
        # ___qtablewidgetitem4.setText(QCoreApplication.translate("FileSearchDialog", "2", None))
        # ___qtablewidgetitem5 = self.tableWidget.verticalHeaderItem(2)
        # ___qtablewidgetitem5.setText(QCoreApplication.translate("FileSearchDialog", "3", None))

        __sortingEnabled = self.tableWidget.isSortingEnabled()
        self.tableWidget.setSortingEnabled(False)
        # ___qtablewidgetitem6 = self.tableWidget.item(0, 0)
        # ___qtablewidgetitem6.setText(
        #     QCoreApplication.translate("FileSearchDialog", "gta v.iso", None)
        # )
        # ___qtablewidgetitem7 = self.tableWidget.item(0, 1)
        # ___qtablewidgetitem7.setText(QCoreApplication.translate("FileSearchDialog", "aaryak", None))
        # ___qtablewidgetitem8 = self.tableWidget.item(0, 2)
        # ___qtablewidgetitem8.setText(
        #     QCoreApplication.translate("FileSearchDialog", "76.1 GB", None)
        # )
        # ___qtablewidgetitem9 = self.tableWidget.item(1, 0)
        # ___qtablewidgetitem9.setText(
        #     QCoreApplication.translate("FileSearchDialog", "gta v repack.iso", None)
        # )
        # ___qtablewidgetitem10 = self.tableWidget.item(1, 1)
        # ___qtablewidgetitem10.setText(QCoreApplication.translate("FileSearchDialog", "harsh", None))
        # ___qtablewidgetitem11 = self.tableWidget.item(1, 2)
        # ___qtablewidgetitem11.setText(QCoreApplication.translate("FileSearchDialog", "58 GB", None))
        # ___qtablewidgetitem12 = self.tableWidget.item(2, 0)
        # ___qtablewidgetitem12.setText(
        #     QCoreApplication.translate("FileSearchDialog", "gta vice city.zip", None)
        # )
        # ___qtablewidgetitem13 = self.tableWidget.item(2, 1)
        # ___qtablewidgetitem13.setText(QCoreApplication.translate("FileSearchDialog", "ani", None))
        # ___qtablewidgetitem14 = self.tableWidget.item(2, 2)
        # ___qtablewidgetitem14.setText(
        #     QCoreApplication.translate("FileSearchDialog", "49.9 GB", None)
        # )
        self.tableWidget.setSortingEnabled(__sortingEnabled)

        header = self.tableWidget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)

        self.tableWidget.setSelectionBehavior(QTableView.SelectRows)
        self.tableWidget.setSelectionMode(QTableView.SingleSelection)

        self.btn_Download.setText(QCoreApplication.translate("FileSearchDialog", "Download", None))

    # retranslateUi

    def search(self, mutex):
        if not self.lineEdit.text().strip():
            return

        try:
            self.tableWidget.clearContents()
            search_query = self.lineEdit.text()
            search_query_bytes = search_query.encode(FMT)
            search_query_header = (
                f"{HeaderCode.FILE_SEARCH.value}{len(search_query_bytes):<{HEADER_MSG_LEN}}".encode(
                    FMT
                )
            )
            mutex.lock("file search")
            self.client_send_socket.send(search_query_header + search_query_bytes)
            res_header = self.client_send_socket.recv(HEADER_TYPE_LEN).decode(FMT)
            res_len = int(self.client_send_socket.recv(HEADER_MSG_LEN).decode(FMT).strip())
            if res_header == HeaderCode.FILE_SEARCH.value:
                res_data: list[ItemSearchResult] = msgpack.unpackb(
                    recvall(self.client_send_socket, res_len)
                )
                mutex.unlock("file search")
                logging.debug(f"{pprint(res_data)}")
                self.tableWidget.setRowCount(len(res_data))
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
                    twItem_SearchItemSize.setText(
                        convert_size(item["data"]["size"]) if item["data"]["size"] else "NA"
                    )
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
                mutex.unlock("file search")
                logging.error(f"Could not search files: {err.msg}")
            else:
                logging.error("invalid header type in search response")
                mutex.unlock("file search")
        except Exception as e:
            logging.exception(f"Error while searching files: {e}")
        return

    def on_selection_changed(self):
        global selected_item
        if len(self.tableWidget.selectedItems()):
            selected_item = self.tableWidget.selectedItems()[0].data(1)
            logging.debug(selected_item)

    def download(self, Dialog):
        self.start_download.emit(selected_item)
        Dialog.close()
