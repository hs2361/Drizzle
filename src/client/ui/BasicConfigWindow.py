# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'BasicConfigWindow.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *


class Ui_BasicConfigWindow:
    def setupUi(self, InitialSettingsWindow):
        if not InitialSettingsWindow.objectName():
            InitialSettingsWindow.setObjectName("InitialSettingsWindow")
        InitialSettingsWindow.resize(422, 299)
        self.centralwidget = QWidget(InitialSettingsWindow)
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

        self.lineEdit = QLineEdit(self.centralwidget)
        self.lineEdit.setObjectName("lineEdit")

        self.verticalLayout.addWidget(self.lineEdit)

        self.label_2 = QLabel(self.centralwidget)
        self.label_2.setObjectName("label_2")

        self.verticalLayout.addWidget(self.label_2)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.lineEdit_2 = QLineEdit(self.centralwidget)
        self.lineEdit_2.setObjectName("lineEdit_2")

        self.horizontalLayout.addWidget(self.lineEdit_2)

        self.pushButton = QPushButton(self.centralwidget)
        self.pushButton.setObjectName("pushButton")

        self.horizontalLayout.addWidget(self.pushButton)

        self.verticalLayout.addLayout(self.horizontalLayout)

        self.pushButton_2 = QPushButton(self.centralwidget)
        self.pushButton_2.setObjectName("pushButton_2")

        self.verticalLayout.addWidget(self.pushButton_2)

        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.verticalSpacer_3 = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout_2.addItem(self.verticalSpacer_3)

        InitialSettingsWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(InitialSettingsWindow)

        QMetaObject.connectSlotsByName(InitialSettingsWindow)

    # setupUi

    def retranslateUi(self, InitialSettingsWindow):
        InitialSettingsWindow.setWindowTitle(
            QCoreApplication.translate("InitialSettingsWindow", "Basic Details", None)
        )
        self.label.setText(QCoreApplication.translate("InitialSettingsWindow", "Server IP", None))
        self.lineEdit.setPlaceholderText(
            QCoreApplication.translate("InitialSettingsWindow", "Enter Server IP", None)
        )
        self.label_2.setText(
            QCoreApplication.translate("InitialSettingsWindow", "Share Folder Path", None)
        )
        self.lineEdit_2.setPlaceholderText(
            QCoreApplication.translate("InitialSettingsWindow", "Enter Share Folder Path", None)
        )
        self.pushButton.setText(QCoreApplication.translate("InitialSettingsWindow", "Open", None))
        self.pushButton_2.setText(
            QCoreApplication.translate("InitialSettingsWindow", "Continue", None)
        )

    # retranslateUi
