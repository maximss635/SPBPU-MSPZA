
from workers import pe_worker
import threading
import time
import psutil
from gui.mainwindow_ui import Ui_MainWindow
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem
from PyQt5.QtGui import QPalette
from PyQt5.QtCore import Qt

from workers.scanner import Scanner
from workers.net_connection_worker import NetConnectionWorker


class MainWindow(Ui_MainWindow, QMainWindow):

    def __init__(self, settings):
        Ui_MainWindow.__init__(self)
        QMainWindow.__init__(self)

        self._proc_scanner = Scanner()

        self.setupUi(self)

        self._netconnection_worker = NetConnectionWorker()

        self.button_start_scan.clicked.connect(self._on_button_start_scan)
        self.button_stop_scan.clicked.connect(self._on_button_stop_scan)

        self._network_activity_cache = list()

        if hasattr(self, "button_debug"):
            self.button_debug.clicked.connect(lambda: self.debug("debug"))

    def _on_button_start_scan(self):
        self._proc_scanner.scan()

        self.main_table.setRowCount(len(self._proc_scanner.procs()))

        self._netconnection_worker.scan()
        netconnection_model = self._netconnection_worker.get_model()

        for i, proc in enumerate(self._proc_scanner.procs()):
            self.main_table.setItem(i, 0, QTableWidgetItem(str(proc.pid)))

            try:
                full_path = psutil.Process(proc.pid).exe()
            except psutil.AccessDenied:
                full_path = proc.name()

            self.main_table.setItem(i, 1, QTableWidgetItem(full_path))

            net_connection = netconnection_model.get(proc.pid)
            if net_connection:
                self.main_table.setItem(
                    i,
                    2,
                    QTableWidgetItem(
                        "{}:{} -> {}:{}".format(
                            net_connection.laddr.ip,
                            net_connection.laddr.port,
                            net_connection.laddr.ip,
                            net_connection.laddr.port,
                        )
                    ),
                )

                t = f"{proc.name()} ({proc.pid})"
                if t in self._network_activity_cache:
                    self._network_activity_cache.remove(t)
                self._network_activity_cache.append(t)

                self.table_network_activity.setRowCount(len(self._network_activity_cache))
                for i, t in enumerate(self._network_activity_cache):
                    self.table_network_activity.setItem(i, 0, QTableWidgetItem(
                        t
                    ))

            # sections_info = pe_worker.analyze_pe_file(full_path)
            # self.main_table.setItem(i, 3, QTableWidgetItem(
            #     sections_info
            # ))

    def _on_button_stop_scan(self):
        self.debug("_on_button_stop_scan")

        self.table_network_activity.setRowCount(0)

    def debug(self, msg):
        debug_panel = getattr(self, "debug_panel", None)
        if debug_panel:
            self.debug_panel.setPlainText(self.debug_panel.toPlainText() + "\n" + msg)
