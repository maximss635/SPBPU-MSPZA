from gui.ask_process_window_ui import Ui_MainWindow
from PyQt5.QtWidgets import QMainWindow


class AskProcessWindow(Ui_MainWindow, QMainWindow):
    def __init__(self, parent):
        Ui_MainWindow.__init__(self)
        QMainWindow.__init__(self, parent)

        self.setupUi(self)

        self.path_process = None

        self.pushButton.clicked.connect(self._on_button_add)

    def _on_button_add(self):
        self.path_process = self.textEdit.toPlainText()
        self.parent().on_new_proc(self.path_process)
        self.close()
