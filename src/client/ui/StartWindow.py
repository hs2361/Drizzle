# Imports (standard libraries)
import logging
import socket

# Imports (PyPI)
from PyQt5.QtCore import QCoreApplication, QMetaObject
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy, QSpacerItem, QVBoxLayout, QWidget

# Imports (UI components)
from ui.BasicConfigWindow import Ui_BasicConfigWindow

CLIENT_IP = socket.gethostbyname(socket.gethostname())

# Logging configuration
logging.basicConfig(level=logging.DEBUG)


class Ui_StartWindow(QWidget):
    """The start window shown to the user to pick a username

    Attributes
    ----------
    MainWindow
        The main application window object

    Methods
    ----------
    onContinue(Dialog)
        Saves the username and moves to the next window
    """

    def __init__(self, MainWindow):
        super(Ui_StartWindow, self).__init__()
        self.setupUi(MainWindow)

    def setupUi(self, MainWindow) -> None:
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
        self.pushButton.clicked.connect(lambda: self.onContinue(MainWindow))  # type: ignore

        self.horizontalLayout.addWidget(self.pushButton)

        self.verticalLayout.addLayout(self.horizontalLayout)

        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.verticalSpacer = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout_2.addItem(self.verticalSpacer)

        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow) -> None:
        MainWindow.setWindowTitle(QCoreApplication.translate("StartWindow", "Welcome To Drizzle", None))
        self.label.setText(QCoreApplication.translate("StartWindow", "Drizzle", None))
        self.lineEdit.setText("")
        self.lineEdit.setPlaceholderText(QCoreApplication.translate("StartWindow", "Enter Your Username", None))
        self.pushButton.setText(QCoreApplication.translate("StartWindow", "Continue", None))

    def onContinue(self, MainWindow) -> None:
        MainWindow.user_settings["uname"] = self.lineEdit.text()
        logging.debug(f"Username updated, new settings: {MainWindow.user_settings}")
        MainWindow.ui = Ui_BasicConfigWindow(MainWindow)
        self.close()
