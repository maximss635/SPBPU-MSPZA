from PyQt5.QtWidgets import QMainWindow

from mainwindow_ui import Ui_MainWindow


class MainWindow(Ui_MainWindow, QMainWindow):
    def __init__(self):
        Ui_MainWindow.__init__(self)
        QMainWindow.__init__(self)

        self.setupUi(self)

        self.button_start_scan.clicked.connect(self._on_button_start_scan)
        self.button_stop_scan.clicked.connect(self._on_button_stop_scan)

    def _on_button_start_scan(self):
        pass

    def _on_button_stop_scan(self):
        pass
