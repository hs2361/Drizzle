import json
import logging
import socket
import sys

from PyQt5.QtWidgets import QApplication, QMainWindow
from ui.DrizzleMainWindow import Ui_DrizzleMainWindow
from ui.StartWindow import Ui_StartWindow

sys.path.append("../")
from utils.constants import USER_SETTINGS_PATH
from utils.types import UserSettings

CLIENT_IP = socket.gethostbyname(socket.gethostname())
logging.basicConfig(level=logging.DEBUG)


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.user_settings: UserSettings = {}
        try:
            with USER_SETTINGS_PATH.open(mode="r") as user_settings_file:
                self.user_settings = json.load(user_settings_file)
            self.ui = Ui_DrizzleMainWindow(self)
        except Exception:
            logging.info("User Settings not found, starting from scratch")
            self.ui = Ui_StartWindow(self)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())
