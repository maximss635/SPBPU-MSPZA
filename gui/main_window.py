import psutil
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem, QWidget

from gui.main_window_ui import Ui_MainWindow
from gui.ask_process_window import AskProcessWindow
from workers.net_connection_worker import NetConnectionWorker
from workers.scanner import Scanner
from workers.pe_worker import analyze_pe_file


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

        self.tabWidget.setTabText(0, "Autoscan")
        self.tabWidget.setTabText(1, "Manually")

        self.button_add.clicked.connect(self._on_button_add)

    @staticmethod
    def _get_full_path_of_proc(proc):
        try:
            return psutil.Process(proc.pid).exe()
        except Exception:
            return proc.name()

    def _get_printable_proc_information(self, proc, netconnection_model):
        full_path = self._get_full_path_of_proc(proc)

        network_activity_str = None

        self._netconnection_worker.scan()

        net_connection = netconnection_model.get(proc.pid)
        if net_connection:
            network_activity_str = "{}:{} -> {}:{}".format(
                net_connection.laddr.ip,
                net_connection.laddr.port,
                net_connection.laddr.ip,
                net_connection.laddr.port,
            )

        self._update_network_cache(proc)

        return full_path, network_activity_str

    def _update_network_cache(self, proc):
        t = f"{proc.name()} ({proc.pid})"
        if t in self._network_activity_cache:
            self._network_activity_cache.remove(t)
        self._network_activity_cache.append(t)

        self.table_network_activity.setRowCount(len(self._network_activity_cache))
        for i, t in enumerate(self._network_activity_cache):
            self.table_network_activity.setItem(i, 0, QTableWidgetItem(t))

    def _on_button_start_scan(self):
        self._proc_scanner.scan()
        self._netconnection_worker.scan()

        netconnection_model = self._netconnection_worker.get_model()

        self.main_table.setRowCount(len(self._proc_scanner.procs()))

        for i, proc in enumerate(self._proc_scanner.procs()):
            full_path, network_activity = self._get_printable_proc_information(proc, netconnection_model)

            print("Add to printable table", full_path, network_activity)

            self._put_to_table(self.main_table, (proc.pid, full_path, network_activity), i)

    @staticmethod
    def _put_to_table(table, printable_entity, row_num):
        table.setItem(row_num, 0, QTableWidgetItem(str(printable_entity[0])))
        table.setItem(row_num, 1, QTableWidgetItem(str(printable_entity[1])))
        table.setItem(row_num, 2, QTableWidgetItem(str(printable_entity[2])))

    def _on_button_stop_scan(self):
        self.debug("_on_button_stop_scan")

        self.table_network_activity.setRowCount(0)

    def _on_button_add(self):
        self.window = AskProcessWindow(self)
        self.window.show()

        print(self.window.path_process)

    def on_new_proc(self, path_proc):
        print("on_new_proc", path_proc)

        result = analyze_pe_file(path_proc)

        rows = self.main_table_2.rowCount()
        self.main_table_2.setRowCount(rows + 1)
        self.main_table_2.setItem(rows, 0, QTableWidgetItem(path_proc))
        self.main_table_2.setItem(rows, 1, QTableWidgetItem(str(result)))

    def debug(self, msg):
        debug_panel = getattr(self, "debug_panel", None)
        if debug_panel:
            self.debug_panel.setPlainText(self.debug_panel.toPlainText() + "\n" + msg)
