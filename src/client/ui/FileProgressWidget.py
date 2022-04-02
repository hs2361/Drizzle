# Imports (standard libraries)
import sys
from pathlib import Path

# Imports (PyPI)
from PyQt5.QtCore import QCoreApplication, QMetaObject, QSize, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QHBoxLayout, QLabel, QProgressBar, QPushButton, QSizePolicy, QWidget

# Imports (utilities)
sys.path.append("../")
from utils.helpers import convert_size


class Ui_FileProgressWidget(QWidget):
    """A widget containing a progress bar and resume/pause button along with information about file downloads

    Attributes
    ----------
    Widget
        The widget object
    item_path : Path
        The path to the file item being downloaded
    total : int
        The total size of the download in bytes
    pause_signal : pyqtSignal | None
        A signal that is emitted when the pause button is pressed
    resume_signal : pyqtSignal | None
        A signal that is emitted when the resume button is pressed
    allow_pause : bool
        Indicates whether the user can pause this download

    Methods
    ----------
    update_progress(new_val: int)
        Updates the progress bar
    toggle_download()
        Toggles the download (resume/pause)
    total : int
        The total size of the download in bytes
    pause_signal : pyqtSignal
        A signal that is emitted when the pause button is pressed
    resume_signal : pyqtSignal
        A signal that is emitted when the resume button is
    """

    def __init__(
        self,
        Widget,
        item_path: Path,
        total: int,
        pause_signal: pyqtSignal | None,
        resume_signal: pyqtSignal | None,
        allow_pause: bool = True,
    ):
        super(Ui_FileProgressWidget, self).__init__()
        self.path = item_path
        self.total = total
        self.fmt_total = convert_size(total)
        self.pause_signal = pause_signal
        self.resume_signal = resume_signal
        self.allow_pause = allow_pause
        self.paused = False
        self.setupUi(Widget, total)

    def update_progress(self, new_val: int) -> None:
        """Updates the progress bar to new_val

        Parameters
        ----------
        new_val : int
            The new value to which to update the progress bar
        """

        converted_size = convert_size(new_val)
        self.progressBar.setFormat(f"{converted_size}/{self.fmt_total}")
        self.progressBar.setValue(int(10000 * new_val / self.total))

    def toggle_download(self):
        """Switches between resuming and pausing the download and emits the resume and pause signals"""

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
        self.progressBar.setMaximum(10000)
        self.progressBar.setObjectName("progressBar")

        self.horizontalLayout_2.addWidget(self.progressBar)

        if self.allow_pause:
            self.btn_Toggle = QPushButton(Widget)
            self.btn_Toggle.setObjectName("pushButton")
            self.btn_Toggle.clicked.connect(self.toggle_download)  # type: ignore
            sizePolicy2 = QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            sizePolicy2.setHorizontalStretch(0)
            sizePolicy2.setVerticalStretch(0)
            self.btn_Toggle.setSizePolicy(sizePolicy2)
            self.btn_Toggle.setMinimumSize(QSize(40, 40))
            self.btn_Toggle.setMaximumSize(QSize(40, 40))
            self.horizontalLayout_2.addWidget(self.btn_Toggle)

        self.horizontalLayout.addLayout(self.horizontalLayout_2)

        self.retranslateUi()

        QMetaObject.connectSlotsByName(Widget)

    def retranslateUi(self):
        self.label.setText(QCoreApplication.translate("Widget", f"{self.path.name}", None))
        self.label.setToolTip(str(self.path))
        if self.allow_pause:
            self.btn_Toggle.setText(QCoreApplication.translate("Widget", "⏸", None))
