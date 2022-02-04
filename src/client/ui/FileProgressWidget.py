import sys
from pathlib import Path

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

sys.path.append("../")


class Ui_FileProgressWidget(QWidget):
    def __init__(self, Widget, item_path: Path):
        super(Ui_FileProgressWidget, self).__init__()
        self.path = item_path
        self.setupUi(Widget)

    def update_progress(self, new_val: float):
        self.progressBar.setValue(int(new_val))

    def setupUi(self, Widget):
        if not Widget.objectName():
            Widget.setObjectName("Form")
        # Widget.resize(648, 50)
        sizePolicy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Widget.sizePolicy().hasHeightForWidth())
        Widget.setSizePolicy(sizePolicy)
        self.horizontalLayout = QHBoxLayout(Widget)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label = QLabel(Widget)
        self.label.setObjectName("label")
        sizePolicy1 = QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
        sizePolicy1.setHorizontalStretch(0)
        sizePolicy1.setVerticalStretch(0)
        sizePolicy1.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy1)
        self.label.setMinimumSize(QSize(120, 0))
        self.label.setMaximumSize(QSize(120, 16777215))
        self.label.setBaseSize(QSize(0, 0))
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setWordWrap(False)

        self.horizontalLayout_2.addWidget(self.label)

        self.progressBar = QProgressBar(Widget)
        self.progressBar.setObjectName("progressBar")

        self.horizontalLayout_2.addWidget(self.progressBar)

        self.pushButton = QPushButton(Widget)
        self.pushButton.setObjectName("pushButton")

        self.horizontalLayout_2.addWidget(self.pushButton)

        self.horizontalLayout.addLayout(self.horizontalLayout_2)

        self.retranslateUi(Widget)

        QMetaObject.connectSlotsByName(Widget)

    # setupUi

    def retranslateUi(self, Widget):
        self.label.setText(QCoreApplication.translate("Widget", f"{self.path.name}", None))
        self.label.setToolTip(str(self.path))
        self.pushButton.setText(QCoreApplication.translate("Widget", "Pause", None))

    # retranslateUi