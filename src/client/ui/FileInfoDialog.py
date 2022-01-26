# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'FileInfoDialog.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *


class Ui_FileInfoDialog(object):
    def setupUi(self, Dialog):
        if not Dialog.objectName():
            Dialog.setObjectName("Dialog")
        Dialog.resize(640, 231)
        self.verticalLayout_2 = QVBoxLayout(Dialog)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.verticalLayout.setContentsMargins(10, -1, 10, -1)
        self.label = QLabel(Dialog)
        self.label.setObjectName("label")
        font = QFont()
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)

        self.verticalLayout.addWidget(self.label, 0, Qt.AlignTop)

        self.formLayout = QFormLayout()
        self.formLayout.setObjectName("formLayout")
        self.formLayout.setSizeConstraint(QLayout.SetDefaultConstraint)
        self.formLayout.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.formLayout.setRowWrapPolicy(QFormLayout.DontWrapRows)
        self.label_2 = QLabel(Dialog)
        self.label_2.setObjectName("label_2")
        self.label_2.setMargin(10)

        self.formLayout.setWidget(0, QFormLayout.LabelRole, self.label_2)

        self.label_3 = QLabel(Dialog)
        self.label_3.setObjectName("label_3")
        self.label_3.setMaximumSize(QSize(200, 16777215))

        self.formLayout.setWidget(0, QFormLayout.FieldRole, self.label_3)

        self.label_4 = QLabel(Dialog)
        self.label_4.setObjectName("label_4")
        self.label_4.setMargin(10)

        self.formLayout.setWidget(1, QFormLayout.LabelRole, self.label_4)

        self.label_5 = QLabel(Dialog)
        self.label_5.setObjectName("label_5")
        self.label_5.setMaximumSize(QSize(200, 16777215))

        self.formLayout.setWidget(1, QFormLayout.FieldRole, self.label_5)

        self.label_6 = QLabel(Dialog)
        self.label_6.setObjectName("label_6")
        self.label_6.setMargin(10)

        self.formLayout.setWidget(2, QFormLayout.LabelRole, self.label_6)

        self.textBrowser = QTextBrowser(Dialog)
        self.textBrowser.setObjectName("textBrowser")
        sizePolicy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.textBrowser.sizePolicy().hasHeightForWidth())
        self.textBrowser.setSizePolicy(sizePolicy)
        self.textBrowser.setMaximumSize(QSize(16777215, 50))
        self.textBrowser.setAcceptRichText(False)

        self.formLayout.setWidget(2, QFormLayout.FieldRole, self.textBrowser)

        self.label_7 = QLabel(Dialog)
        self.label_7.setObjectName("label_7")
        self.label_7.setMargin(10)

        self.formLayout.setWidget(3, QFormLayout.LabelRole, self.label_7)

        self.label_8 = QLabel(Dialog)
        self.label_8.setObjectName("label_8")

        self.formLayout.setWidget(3, QFormLayout.FieldRole, self.label_8)

        self.verticalLayout.addLayout(self.formLayout)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout.addItem(self.horizontalSpacer)

        self.pushButton_2 = QPushButton(Dialog)
        self.pushButton_2.setObjectName("pushButton_2")

        self.horizontalLayout.addWidget(self.pushButton_2)

        self.pushButton = QPushButton(Dialog)
        self.pushButton.setObjectName("pushButton")

        self.horizontalLayout.addWidget(self.pushButton)

        self.verticalLayout.addLayout(self.horizontalLayout)

        self.verticalLayout.setStretch(0, 1)
        self.verticalLayout.setStretch(1, 10)

        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.retranslateUi(Dialog)

        QMetaObject.connectSlotsByName(Dialog)

    # setupUi

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QCoreApplication.translate("Dialog", "File Info", None))
        self.label.setText(QCoreApplication.translate("Dialog", "msoffice.zip", None))
        self.label_2.setText(QCoreApplication.translate("Dialog", "Type", None))
        self.label_3.setText(QCoreApplication.translate("Dialog", "File", None))
        self.label_4.setText(QCoreApplication.translate("Dialog", "Size", None))
        self.label_5.setText(QCoreApplication.translate("Dialog", "1.8GiB", None))
        self.label_6.setText(QCoreApplication.translate("Dialog", "File Hash", None))
        self.textBrowser.setHtml(
            QCoreApplication.translate(
                "Dialog",
                '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n'
                '<html><head><meta name="qrichtext" content="1" /><style type="text/css">\n'
                "p, li { white-space: pre-wrap; }\n"
                "</style></head><body style=\" font-family:'Noto Sans'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
                '<p style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;">nkshdfjkghskjfdhgkjsghfdjkhhgsjkdfhbjsdhgfjhsdhfjkghsjkhdhfhjkjsgdfjhbsdjhfgjkhsdgdfjhgs</p></body></html>',
                None,
            )
        )
        self.label_7.setText(QCoreApplication.translate("Dialog", "Owner", None))
        self.label_8.setText(
            QCoreApplication.translate("Dialog", "RichardRoe12 @192.168.0.19", None)
        )
        self.pushButton_2.setText(QCoreApplication.translate("Dialog", "Close", None))
        self.pushButton.setText(QCoreApplication.translate("Dialog", "Download", None))

    # retranslateUi
