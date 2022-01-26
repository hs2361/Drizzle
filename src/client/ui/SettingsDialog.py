# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'SettingsDialog.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *


class Ui_SettingsDialog(object):
    def setupUi(self, Dialog):
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
        self.label.setMargin(10)

        self.formLayout.setWidget(0, QFormLayout.LabelRole, self.label)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.lineEdit = QLineEdit(Dialog)
        self.lineEdit.setObjectName("lineEdit")

        self.horizontalLayout.addWidget(self.lineEdit)

        self.pushButton = QPushButton(Dialog)
        self.pushButton.setObjectName("pushButton")

        self.horizontalLayout.addWidget(self.pushButton)

        self.formLayout.setLayout(0, QFormLayout.FieldRole, self.horizontalLayout)

        self.label_2 = QLabel(Dialog)
        self.label_2.setObjectName("label_2")
        self.label_2.setMargin(10)

        self.formLayout.setWidget(1, QFormLayout.LabelRole, self.label_2)

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.lineEdit_2 = QLineEdit(Dialog)
        self.lineEdit_2.setObjectName("lineEdit_2")

        self.horizontalLayout_2.addWidget(self.lineEdit_2)

        self.pushButton_2 = QPushButton(Dialog)
        self.pushButton_2.setObjectName("pushButton_2")

        self.horizontalLayout_2.addWidget(self.pushButton_2)

        self.formLayout.setLayout(1, QFormLayout.FieldRole, self.horizontalLayout_2)

        self.label_3 = QLabel(Dialog)
        self.label_3.setObjectName("label_3")
        self.label_3.setMargin(10)

        self.formLayout.setWidget(2, QFormLayout.LabelRole, self.label_3)

        self.lineEdit_3 = QLineEdit(Dialog)
        self.lineEdit_3.setObjectName("lineEdit_3")

        self.formLayout.setWidget(2, QFormLayout.FieldRole, self.lineEdit_3)

        self.lineEdit_4 = QLineEdit(Dialog)
        self.lineEdit_4.setObjectName("lineEdit_4")

        self.formLayout.setWidget(3, QFormLayout.FieldRole, self.lineEdit_4)

        self.label_4 = QLabel(Dialog)
        self.label_4.setObjectName("label_4")
        self.label_4.setMargin(10)

        self.formLayout.setWidget(3, QFormLayout.LabelRole, self.label_4)

        self.verticalLayout.addLayout(self.formLayout)

        self.horizontalLayout_3 = QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_3.addItem(self.horizontalSpacer)

        self.pushButton_4 = QPushButton(Dialog)
        self.pushButton_4.setObjectName("pushButton_4")

        self.horizontalLayout_3.addWidget(self.pushButton_4)

        self.pushButton_3 = QPushButton(Dialog)
        self.pushButton_3.setObjectName("pushButton_3")

        self.horizontalLayout_3.addWidget(self.pushButton_3)

        self.verticalLayout.addLayout(self.horizontalLayout_3)

        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.retranslateUi(Dialog)

        QMetaObject.connectSlotsByName(Dialog)

    # setupUi

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QCoreApplication.translate("Dialog", "Settings", None))
        self.label.setText(QCoreApplication.translate("Dialog", "Share Folder Path", None))
        self.lineEdit.setText(
            QCoreApplication.translate("Dialog", "/home/john/Drizzle/share/", None)
        )
        self.pushButton.setText(QCoreApplication.translate("Dialog", "Select", None))
        self.label_2.setText(QCoreApplication.translate("Dialog", "Downloads Folder Path", None))
        self.lineEdit_2.setText(QCoreApplication.translate("Dialog", "/home/john/Downloads/", None))
        self.pushButton_2.setText(QCoreApplication.translate("Dialog", "Select", None))
        self.label_3.setText(QCoreApplication.translate("Dialog", "Username", None))
        self.lineEdit_3.setText(QCoreApplication.translate("Dialog", "john_doe_", None))
        self.lineEdit_4.setText(QCoreApplication.translate("Dialog", "192.168.0.4", None))
        self.label_4.setText(QCoreApplication.translate("Dialog", "Server IP", None))
        self.pushButton_4.setText(QCoreApplication.translate("Dialog", "Cancel", None))
        self.pushButton_3.setText(QCoreApplication.translate("Dialog", "Apply", None))

    # retranslateUi
