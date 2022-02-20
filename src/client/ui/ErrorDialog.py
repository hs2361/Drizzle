# Imports (standard libraries)
import sys

# Imports (PyPI)
from PyQt5.QtCore import QCoreApplication, QMetaObject, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QSpacerItem, QVBoxLayout

# Imports (utilities)
sys.path.append("../")
from ui.SettingsDialog import Ui_SettingsDialog

from utils.types import UserSettings


class Ui_ErrorDialog(QDialog):
    """An error dialog that displays an error message and optionally, allows to open the settings

    Attributes
    ----------
    Dialog : QDialog
        The dialog object
    error_log : str
        The error text to be displayed in the dialog
    settings : UserSettings | None
        If not None, provides an option to open the settings dialog
    """

    def __init__(self, Dialog: QDialog, error_log: str, settings: UserSettings | None):
        super(Ui_ErrorDialog, self).__init__()
        self.error_log = error_log
        self.settings = settings
        self.setupUi(Dialog)

    def setupUi(self, Dialog):
        if not Dialog.objectName():
            Dialog.setObjectName("Dialog")
        Dialog.resize(640, 203)
        self.verticalLayout = QVBoxLayout(Dialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QLabel(Dialog)
        self.label.setObjectName("label")
        font = QFont()
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)

        self.verticalLayout.addWidget(self.label, 0, Qt.AlignTop)

        self.label_2 = QLabel(Dialog)
        self.label_2.setObjectName("label_2")
        sizePolicy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_2.sizePolicy().hasHeightForWidth())
        self.label_2.setSizePolicy(sizePolicy)
        self.label_2.setTextFormat(Qt.PlainText)
        self.label_2.setScaledContents(False)
        self.label_2.setWordWrap(True)

        self.verticalLayout.addWidget(self.label_2, 0, Qt.AlignTop)

        self.verticalSpacer = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout.addItem(self.verticalSpacer)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout.addItem(self.horizontalSpacer)

        if self.settings is not None:
            self.btn_Settings = QPushButton(Dialog)
            self.btn_Settings.setObjectName("pushButton_2")
            self.horizontalLayout.addWidget(self.btn_Settings)

        self.btn_Close = QPushButton(Dialog)
        self.btn_Close.setObjectName("pushButton")

        self.horizontalLayout.addWidget(self.btn_Close)

        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(Dialog)

        QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QCoreApplication.translate("Dialog", "Drizzle: An error occurred", None))
        self.label.setText(QCoreApplication.translate("Dialog", "An error occurred", None))
        self.label_2.setText(
            QCoreApplication.translate(
                "Dialog",
                self.error_log,
                None,
            )
        )

        self.btn_Close.setText(QCoreApplication.translate("Dialog", "Close", None))
        self.btn_Close.clicked.connect(Dialog.close)

        # Don't show the settings button if settings was None
        if self.settings is not None:
            self.btn_Settings.setText(QCoreApplication.translate("Dialog", "Open Settings", None))
            self.btn_Settings.clicked.connect(self.open_settings)

    def open_settings(self):
        """Opens the settings dialog with the given settings"""

        settings_dialog = QDialog()
        settings_dialog.ui = Ui_SettingsDialog(settings_dialog, self.settings)
        settings_dialog.exec()
