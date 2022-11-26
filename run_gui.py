import json
import sys

from PyQt5.QtWidgets import QApplication

from gui.mainwindow import MainWindow
from utils import Logger

LOGGER = Logger(__name__)


def _load_settings():
    if sys.platform == "linux":
        path_settings = "settings_linux.json"
        LOGGER.debug("Platform is linux -> path settings = %s", path_settings)
    else:
        path_settings = "settings_windows.json"
        LOGGER.debug("Platform is windows -> path settings = %s", path_settings)

    with open(path_settings, "r") as f:
        return json.load(f)


if __name__ == "__main__":
    settings = _load_settings()

    app = QApplication(sys.argv)
    window = MainWindow(settings)
    window.show()
    app.exec()
