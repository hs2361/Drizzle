import sys
from pathlib import Path

from PyQt5.QtCore import QCoreApplication, QMetaObject, QSize, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QHBoxLayout, QLabel, QProgressBar, QPushButton, QSizePolicy, QWidget

sys.path.append("../")
from utils.helpers import convert_size


class Ui_FileProgressWidget(QWidget):
    def __init__(
        self,
        Widget,
        item_path: Path,
        total: int,
        pause_signal: pyqtSignal,
        resume_signal: pyqtSignal,
    ):
        super(Ui_FileProgressWidget, self).__init__()
        self.path = item_path
        self.total = total
        self.fmt_total = convert_size(total)
        self.pause_signal = pause_signal
        self.resume_signal = resume_signal
        self.setupUi(Widget, total)
        self.paused = False

    def update_progress(self, new_val: int):
        converted_size = convert_size(new_val)
        self.progressBar.setFormat(f"{converted_size}/{self.fmt_total}")
        self.progressBar.setValue(new_val)

    def toggle_download(self):
        if not self.paused:
            self.pause_signal.emit(self.path)
            self.btn_Toggle.setText("▶")
            self.paused = True
        else:
            self.resume_signal.emit(self.path)
            self.btn_Toggle.setText("⏸")
            self.paused = False

    def setupUi(self, Widget, total: int):
        if not Widget.objectName():
            Widget.setObjectName("Form")
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
        self.progressBar.setMaximum(total)
        self.progressBar.setObjectName("progressBar")

        self.horizontalLayout_2.addWidget(self.progressBar)

        self.btn_Toggle = QPushButton(Widget)
        self.btn_Toggle.setObjectName("pushButton")
        self.btn_Toggle.clicked.connect(self.toggle_download)  # type: ignore
        self.horizontalLayout_2.addWidget(self.btn_Toggle)

        self.horizontalLayout.addLayout(self.horizontalLayout_2)

        self.retranslateUi()

        QMetaObject.connectSlotsByName(Widget)

    # setupUi

    def retranslateUi(self):
        self.label.setText(QCoreApplication.translate("Widget", f"{self.path.name}", None))
        self.label.setToolTip(str(self.path))
        self.btn_Toggle.setText(QCoreApplication.translate("Widget", "⏸", None))

    # retranslateUi
