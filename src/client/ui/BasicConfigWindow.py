# Imports (standard libraries)
import json
import logging
import sys
from pathlib import Path

# Imports (PyPI)
from PyQt5.QtCore import QCoreApplication, QMetaObject
from PyQt5.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)

# Imports (UI components)
from ui.DrizzleMainWindow import Ui_DrizzleMainWindow

# Imports (utilities)
sys.path.append("../")
from utils.constants import USER_SETTINGS_PATH


class Ui_BasicConfigWindow(QWidget):
    """The basic configuration window shown to the user to enter server IP and share path"""

    def __init__(self, MainWindow):
        super(Ui_BasicConfigWindow, self).__init__()
        self.setupUi(MainWindow)

    def setupUi(self, MainWindow) -> None:
        if not MainWindow.objectName():
            MainWindow.setObjectName("InitialSettingsWindow")
        MainWindow.resize(422, 299)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_2 = QVBoxLayout(self.centralwidget)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalSpacer_4 = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout_2.addItem(self.verticalSpacer_4)

        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.verticalLayout.setContentsMargins(30, -1, 30, -1)
        self.label = QLabel(self.centralwidget)
        self.label.setObjectName("label")

        self.verticalLayout.addWidget(self.label)

        self.le_serverIp = QLineEdit(self.centralwidget)
        self.le_serverIp.setObjectName("lineEdit")

        self.verticalLayout.addWidget(self.le_serverIp)

        self.label_2 = QLabel(self.centralwidget)
        self.label_2.setObjectName("label_2")

        self.verticalLayout.addWidget(self.label_2)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.le_sharePath = QLineEdit(self.centralwidget)
        self.le_sharePath.setObjectName("lineEdit_2")

        self.horizontalLayout.addWidget(self.le_sharePath)

        self.btn_SelectSharePath = QPushButton(self.centralwidget)
        self.btn_SelectSharePath.setObjectName("pushButton")
        self.btn_SelectSharePath.clicked.connect(self.open_dir_picker)  # type: ignore

        self.horizontalLayout.addWidget(self.btn_SelectSharePath)

        self.verticalLayout.addLayout(self.horizontalLayout)

        self.btn_submit = QPushButton(self.centralwidget)
        self.btn_submit.setObjectName("pushButton_2")
        self.btn_submit.clicked.connect(lambda: self.on_submit(MainWindow))  # type: ignore

        self.verticalLayout.addWidget(self.btn_submit)

        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.verticalSpacer_3 = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout_2.addItem(self.verticalSpacer_3)

        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)

        QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow) -> None:
        MainWindow.setWindowTitle(QCoreApplication.translate("InitialSettingsWindow", "Basic Details", None))
        self.label.setText(QCoreApplication.translate("InitialSettingsWindow", "Server IP", None))
        self.le_serverIp.setPlaceholderText(
            QCoreApplication.translate("InitialSettingsWindow", "Enter Server IP", None)
        )
        self.label_2.setText(QCoreApplication.translate("InitialSettingsWindow", "Share Folder Path", None))
        self.le_sharePath.setPlaceholderText(
            QCoreApplication.translate("InitialSettingsWindow", "Enter Share Folder Path", None)
        )
        self.btn_SelectSharePath.setText(QCoreApplication.translate("InitialSettingsWindow", "Open", None))
        self.btn_submit.setText(QCoreApplication.translate("InitialSettingsWindow", "Continue", None))

    def on_submit(self, MainWindow) -> None:
        """Loads the entered values into the settings and stores them in the settings.json file

        Parameters
        ----------
        MainWindow : MainWindow
            The main application window
        """

        # Get entered values
        MainWindow.user_settings["server_ip"] = self.le_serverIp.text()
        MainWindow.user_settings["share_folder_path"] = self.le_sharePath.text()
        try:
            # Store the settings in the settings.json file
            with USER_SETTINGS_PATH.open(mode="w") as user_settings_file:
                json.dump(MainWindow.user_settings, user_settings_file, indent=4, sort_keys=True)

            # Open the main window
            MainWindow.ui = Ui_DrizzleMainWindow(MainWindow)
            self.close()
        except Exception as e:
            logging.error(f"Could not save User Config: {e}")
            self.close()

    def open_dir_picker(self) -> None:
        """Opens the directory picker to choose a share folder"""

        path = QFileDialog.getExistingDirectory(self, "Select Share Folder", str(Path.home()), QFileDialog.ShowDirsOnly)
        self.le_sharePath.setText(path)
