import json
import logging
import socket
import sys

from PyQt5.QtWidgets import QApplication, QMainWindow
from ui.StartWindow import Ui_StartWindow

# from core.client import send_heartbeat


sys.path.append("../")
from utils.constants import RECV_FOLDER_PATH, USER_SETTINGS_PATH
from utils.types import UserSettings

CLIENT_IP = socket.gethostbyname(socket.gethostname())
logging.basicConfig(level=logging.DEBUG)


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        try:
            self.user_settings: UserSettings = {"downloads_folder_path": str(RECV_FOLDER_PATH)}
            with USER_SETTINGS_PATH.open(mode="r") as user_settings_file:
                self.user_settings = json.load(user_settings_file)
            from ui.DrizzleMainWindow import Ui_DrizzleMainWindow

            self.ui = Ui_DrizzleMainWindow(self)
        except Exception as e:
            logging.error(
                f"User Settings not found, starting from scratch. Cause: {e}", exc_info=True
            )
            self.ui = Ui_StartWindow(self)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())
