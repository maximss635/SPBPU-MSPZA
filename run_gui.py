import json
import sys

from PyQt5.QtWidgets import QApplication

from gui.main_window import MainWindow
from utils import Logger

LOGGER = Logger(__name__)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()
