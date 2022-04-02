# Imports (standard libraries)
import json
import os
import sys
from pathlib import Path

# Imports (PyPI)
from PyQt5.QtCore import QCoreApplication, QMetaObject
from PyQt5.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
)

# Imports (utilities)
sys.path.append("../")
from utils.constants import USER_SETTINGS_PATH
from utils.types import UserSettings


class Ui_SettingsDialog(QDialog):
    """A dialog that allows the user to change the application settings

    Attributes
    ----------
    Dialog
        The dialog object
    settings : UserSettings
        The existing settings that are displayed in the dialog

    Methods
    ----------
    apply_settings(Dialog)
        Saves the entered settings into the file
    open_dir_picker(is_share_path: bool)
        Opens the directory picker dialog
    """

    def __init__(self, Dialog, settings: UserSettings):
        super(Ui_SettingsDialog, self).__init__()
        self.settings = settings
        self.setupUi(Dialog)

    def setupUi(self, Dialog) -> None:
        if not Dialog.objectName():
            Dialog.setObjectName("Dialog")
        Dialog.resize(640, 236)
        self.verticalLayout_2 = QVBoxLayout(Dialog)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.verticalLayout.setContentsMargins(10, -1, 10, -1)
        self.formLayout = QFormLayout()
        self.formLayout.setObjectName("formLayout")
        self.label = QLabel(Dialog)
        self.label.setObjectName("label")

        self.formLayout.setWidget(0, QFormLayout.LabelRole, self.label)  # type: ignore

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.le_SharePath = QLineEdit(Dialog)
        self.le_SharePath.setObjectName("lineEdit")

        self.horizontalLayout.addWidget(self.le_SharePath)

        self.btn_SelectShare = QPushButton(Dialog)
        self.btn_SelectShare.setObjectName("pushButton")
        self.btn_SelectShare.clicked.connect(lambda: self.open_dir_picker(True))  # type: ignore

        self.horizontalLayout.addWidget(self.btn_SelectShare)

        self.formLayout.setLayout(0, QFormLayout.FieldRole, self.horizontalLayout)  # type: ignore

        self.label_2 = QLabel(Dialog)
        self.label_2.setObjectName("label_2")

        self.formLayout.setWidget(1, QFormLayout.LabelRole, self.label_2)  # type: ignore

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.le_DownloadsPath = QLineEdit(Dialog)
        self.le_DownloadsPath.setObjectName("lineEdit_2")

        self.horizontalLayout_2.addWidget(self.le_DownloadsPath)

        self.btn_SelectDownload = QPushButton(Dialog)
        self.btn_SelectDownload.setObjectName("pushButton_2")
        self.btn_SelectDownload.clicked.connect(lambda: self.open_dir_picker(False))  # type: ignore

        self.horizontalLayout_2.addWidget(self.btn_SelectDownload)

        self.formLayout.setLayout(1, QFormLayout.FieldRole, self.horizontalLayout_2)  # type: ignore

        self.label_3 = QLabel(Dialog)
        self.label_3.setObjectName("label_3")

        self.formLayout.setWidget(2, QFormLayout.LabelRole, self.label_3)  # type: ignore

        self.le_Username = QLineEdit(Dialog)
        self.le_Username.setObjectName("lineEdit_3")

        self.formLayout.setWidget(2, QFormLayout.FieldRole, self.le_Username)  # type: ignore

        self.le_ServerIP = QLineEdit(Dialog)
        self.le_ServerIP.setObjectName("lineEdit_4")

        self.formLayout.setWidget(3, QFormLayout.FieldRole, self.le_ServerIP)  # type: ignore

        self.label_4 = QLabel(Dialog)
        self.label_4.setObjectName("label_4")

        self.formLayout.setWidget(3, QFormLayout.LabelRole, self.label_4)  # type: ignore

        self.toggle = QCheckBox(Dialog)
        self.formLayout.setWidget(4, QFormLayout.FieldRole, self.toggle)  # type: ignore

        self.label_5 = QLabel(Dialog)
        self.label_5.setObjectName("label_5")

        self.formLayout.setWidget(4, QFormLayout.LabelRole, self.label_5)  # type: ignore

        self.formLayout.setSpacing(10)

        self.verticalLayout.addLayout(self.formLayout)

        self.horizontalLayout_3 = QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer)

        self.btn_Cancel = QPushButton(Dialog)
        self.btn_Cancel.setObjectName("pushButton_4")

        self.horizontalLayout_3.addWidget(self.btn_Cancel)

        self.btn_Apply = QPushButton(Dialog)
        self.btn_Apply.setObjectName("pushButton_3")

        self.horizontalLayout_3.addWidget(self.btn_Apply)

        self.verticalLayout.addLayout(self.horizontalLayout_3)

        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.retranslateUi(Dialog)

        QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog) -> None:
        Dialog.setWindowTitle(QCoreApplication.translate("Dialog", "Settings", None))
        self.label.setText(QCoreApplication.translate("Dialog", "Share Folder Path", None))
        self.le_SharePath.setText(QCoreApplication.translate("Dialog", self.settings["share_folder_path"], None))
        self.btn_SelectShare.setText(QCoreApplication.translate("Dialog", "Select", None))
        self.label_2.setText(QCoreApplication.translate("Dialog", "Downloads Folder Path", None))
        self.le_DownloadsPath.setText(
            QCoreApplication.translate("Dialog", self.settings["downloads_folder_path"], None)
        )
        self.btn_SelectDownload.setText(QCoreApplication.translate("Dialog", "Select", None))
        self.label_3.setText(QCoreApplication.translate("Dialog", "Username", None))
        self.le_Username.setText(QCoreApplication.translate("Dialog", self.settings["uname"], None))
        self.le_ServerIP.setText(QCoreApplication.translate("Dialog", self.settings["server_ip"], None))
        self.label_4.setText(QCoreApplication.translate("Dialog", "Server IP", None))
        self.btn_Cancel.setText(QCoreApplication.translate("Dialog", "Cancel", None))
        self.btn_Apply.setText(QCoreApplication.translate("Dialog", "Apply", None))

        self.label_5.setText(QCoreApplication.translate("Dialog", "Show Desktop Notifications", None))

        self.btn_Apply.clicked.connect(lambda: self.apply_settings(Dialog))  # type: ignore
        self.btn_Cancel.clicked.connect(Dialog.close)  # type: ignore
        self.toggle.setChecked(self.settings["show_notifications"])

    def apply_settings(self, Dialog) -> None:
        """
        Gets the entered settings and saves them to the file. Also opens a dialog to restart the application if needed

        Parameters
        ----------
        Dialog
            The dialog object
        """

        new_settings: UserSettings = {}
        new_settings["downloads_folder_path"] = self.le_DownloadsPath.text()
        new_settings["share_folder_path"] = self.le_SharePath.text()
        new_settings["server_ip"] = self.le_ServerIP.text()
        new_settings["uname"] = self.le_Username.text()
        new_settings["show_notifications"] = self.toggle.isChecked()

        with USER_SETTINGS_PATH.open(mode="w") as user_settings_file:
            json.dump(new_settings, user_settings_file)

        if new_settings != self.settings:
            message_box = QMessageBox(Dialog)
            message_box.setIcon(QMessageBox.Information)
            message_box.setWindowTitle("Settings Changed")
            message_box.setText("New settings will be applied after restart")
            message_box.addButton(QMessageBox.Close)
            btn_restart = message_box.addButton("Restart Now", QMessageBox.NoRole)
            btn_restart.clicked.connect(lambda: os.execl(sys.executable, sys.executable, "-m", "client.app"))  # type: ignore
            message_box.exec()

        self.settings = new_settings
        Dialog.close()

    def open_dir_picker(self, is_share_path: bool) -> None:
        """Opens the directory picker dialog to choose the share folder path or downloads folder path

        Parameters
        ----------
        is_share_path : bool
            Whether or not this picker is for choosing the share folder path
        """

        title = "Select Share Folder" if is_share_path else "Select Downloads Folder"
        path = QFileDialog.getExistingDirectory(self, title, str(Path.home()), QFileDialog.ShowDirsOnly)
        if is_share_path:
            self.le_SharePath.setText(path)
        else:
            self.le_DownloadsPath.setText(path)
