import logging
import socket

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from ui.BasicConfigWindow import Ui_BasicConfigWindow

CLIENT_IP = socket.gethostbyname(socket.gethostname())
logging.basicConfig(level=logging.DEBUG)


class Ui_StartWindow(QWidget):
    def __init__(self, MainWindow):
        super(Ui_StartWindow, self).__init__()
        self.setupUi(MainWindow)

    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName("StartWindow")
        MainWindow.resize(342, 264)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_2 = QVBoxLayout(self.centralwidget)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalSpacer_2 = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout_2.addItem(self.verticalSpacer_2)

        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.verticalLayout.setContentsMargins(20, -1, 20, -1)
        self.label = QLabel(self.centralwidget)
        self.label.setObjectName("label")
        font = QFont()
        font.setPointSize(18)
        self.label.setFont(font)

        self.verticalLayout.addWidget(self.label)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.lineEdit = QLineEdit(self.centralwidget)
        self.lineEdit.setObjectName("lineEdit")

        self.horizontalLayout.addWidget(self.lineEdit)

        self.pushButton = QPushButton(self.centralwidget)
        self.pushButton.setObjectName("pushButton")
        self.pushButton.clicked.connect(lambda: self.onContinue(MainWindow))

        self.horizontalLayout.addWidget(self.pushButton)

        self.verticalLayout.addLayout(self.horizontalLayout)

        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.verticalSpacer = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout_2.addItem(self.verticalSpacer)

        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        # self.center()
        QMetaObject.connectSlotsByName(MainWindow)

    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(
            QCoreApplication.translate("StartWindow", "Welcome To Drizzle", None)
        )
        self.label.setText(QCoreApplication.translate("StartWindow", "Drizzle", None))
        self.lineEdit.setText("")
        self.lineEdit.setPlaceholderText(
            QCoreApplication.translate("StartWindow", "Enter Your Username", None)
        )
        self.pushButton.setText(QCoreApplication.translate("StartWindow", "Continue", None))

    # retranslateUi

    def onContinue(self, MainWindow):
        MainWindow.user_settings["uname"] = self.lineEdit.text()
        logging.debug(f"Username updated, new settings: {MainWindow.user_settings}")
        MainWindow.ui = Ui_BasicConfigWindow(MainWindow)
        self.close()
        # StartWindow.front_widget = 1
        # StartWindow.pages[1].show()
        # StartWindow.switch_page(StartWindow.front_widget)
