import threading
import time

from gui.mainwindow_ui import Ui_MainWindow
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem
from PyQt5.QtGui import QPalette
from PyQt5.QtCore import Qt

from workers.scanner import Scanner
from workers.netstat_worker import NetstatWorker


class MainWindow(Ui_MainWindow, QMainWindow):
    class Thread(threading.Thread):
        def __init__(self, netstat_worker, main_window):
            threading.Thread.__init__(self)

            self._netstat_worker = netstat_worker
            self._main_window = main_window

            self._run_flag = False

        def start(self) -> None:
            self._run_flag = True
            threading.Thread.start(self)

        def run(self) -> None:
            while self._run_flag:
                time.sleep(1)
                model = self._netstat_worker.get_current_model()
                self._main_window.update_network_activity(model)

        def stop(self):
            self._run_flag = False

    def __init__(self, settings):
        Ui_MainWindow.__init__(self)
        QMainWindow.__init__(self)

        self._proc_scanner = Scanner()
        self._netstat_worker = NetstatWorker(settings["netsat_worker"])
        self._thr = self.Thread(self._netstat_worker, self)

        self.setupUi(self)

        self.button_start_scan.clicked.connect(self._on_button_start_scan)
        self.button_stop_scan.clicked.connect(self._on_button_stop_scan)

        self._network_activity_cache = list()

        palette = QPalette()
        palette.setColor(QPalette.Window, Qt.white)
        self.label_network_activity.setPalette(palette)

        if hasattr(self, "button_debug"):
            self.button_debug.clicked.connect(lambda: self.debug("debug"))

    def _on_button_start_scan(self):
        self._netstat_worker.start_scan()
        self._proc_scanner.scan()

        self.main_table.setRowCount(len(self._proc_scanner.procs()))

        for i, proc in enumerate(self._proc_scanner.procs()):
            self.main_table.setItem(i, 0, QTableWidgetItem(str(proc.pid)))
            self.main_table.setItem(i, 1, QTableWidgetItem(str(proc.name())))

        self._thr.start()

    def _on_button_stop_scan(self):
        self.debug("_on_button_stop_scan")

        self._thr.stop()
        self._netstat_worker.stop_scan()

        self.label_network_activity.setText("")

    def debug(self, msg):
        debug_panel = getattr(self, "debug_panel", None)
        if debug_panel:
            self.debug_panel.setPlainText(self.debug_panel.toPlainText() + "\n" + msg)

    def update_network_activity(self, model):
        print("update_network_activity")

        for i in range(self.main_table.rowCount()):
            pid = int(self.main_table.item(i, 0).text())
            programm_name = self.main_table.item(i, 1).text()

            network_activity_entity = model.get(pid)
            if network_activity_entity:
                print(f" --> pid {pid}")
                self.main_table.setItem(
                    i,
                    2,
                    QTableWidgetItem(
                        "{} -> {}".format(
                            network_activity_entity["local_addr"],
                            network_activity_entity["foreign_addr"],
                        )
                    ),
                )

                if programm_name in self._network_activity_cache:
                    self._network_activity_cache.remove(programm_name)
                self._network_activity_cache.append(programm_name)

                text = ""
                for i in self._network_activity_cache:
                    text += f"{i} (pid {pid})"

                self.label_network_activity.setText(text)
