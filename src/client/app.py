# Imports (standard libraries)
import json
import logging
import socket
import sys
from pathlib import Path

# Imports (PyPI)
from PyQt5.QtWidgets import QApplication, QMainWindow

# Imports (utilities)
from utils.constants import RECV_FOLDER_PATH, SHARE_FOLDER_PATH, USER_SETTINGS_PATH
from utils.types import UserSettings

# Create application directories if they don't exist
app_dir = Path.home() / ".Drizzle"
app_dir.mkdir(exist_ok=True)
(app_dir / "logs").mkdir(exist_ok=True)
(app_dir / "db").mkdir(exist_ok=True)
(app_dir / "share").mkdir(exist_ok=True)
(app_dir / "compressed").mkdir(exist_ok=True)
(app_dir / "tmp").mkdir(exist_ok=True)
(app_dir / "direct").mkdir(exist_ok=True)

sys.path.append("client")
from ui.StartWindow import Ui_StartWindow

# Constants
CLIENT_IP = socket.gethostbyname(socket.gethostname())

# Logging configuration
logging.basicConfig(level=logging.DEBUG)


class MainWindow(QMainWindow):
    """The main window of the application

    Methods
    ----------
    closeEvent(event) (Overriden)
        Saves the progress data before exiting the application
    center()
        Centers the window in the screen
    """

    def closeEvent(self, event) -> None:
        """Saves the progress data before exiting the application"""

        logging.debug("Closing main window")
        self.ui.dump_progress_data()
        return super().closeEvent(event)

    def __init__(self):
        super(MainWindow, self).__init__()
        # Center the window
        self.center()
        # Try loading saved settings
        try:
            # Load user settings from settings.json file
            self.user_settings: UserSettings = {
                "share_folder_path": str(SHARE_FOLDER_PATH),
                "downloads_folder_path": str(RECV_FOLDER_PATH),
                "show_notifications": True,
            }
            with USER_SETTINGS_PATH.open(mode="r") as user_settings_file:
                self.user_settings = json.load(user_settings_file)

            # Open the main window
            from ui.DrizzleMainWindow import Ui_DrizzleMainWindow

            self.ui = Ui_DrizzleMainWindow(self)
        except Exception as e:
            # Start from start window otherwise
            logging.error(f"User Settings not found, starting from defaults. Cause: {e}", exc_info=True)
            self.ui = Ui_StartWindow(self)

    def center(self):
        """Centers the main window on the screen"""

        frame_geometry = self.frameGeometry()

        # Find the screen the application is being displayed on
        screen = QApplication.desktop().screenNumber(QApplication.desktop().cursor().pos())
        center_point = QApplication.desktop().screenGeometry(screen).center()

        # Move the window to the center of the screen
        frame_geometry.moveCenter(center_point)
        self.move(frame_geometry.topLeft())


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    # Exit the application when the window is closed
    sys.exit(app.exec())
