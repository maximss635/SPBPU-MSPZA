import socket

import psutil
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem, QWidget

from gui.ask_process_window import AskProcessWindow
from gui.main_window_ui import Ui_MainWindow
from workers.net_connection_worker import NetConnectionWorker
from workers.pe_worker import analyze_pe_file
from workers.scanner import Scanner
from workers.sign_check import check_sign


class MainWindow(Ui_MainWindow, QMainWindow):
    def __init__(self):
        Ui_MainWindow.__init__(self)
        QMainWindow.__init__(self)

        self._proc_scanner = Scanner()

        self.setupUi(self)

        self._netconnection_worker = NetConnectionWorker()

        self.button_start_scan.clicked.connect(self._on_button_start_scan)
        self.button_stop_scan.clicked.connect(self._on_button_stop_scan)
        self.button_clear.clicked.connect(self._on_button_clear)

        self.checkBox_pid.setChecked(True)
        self.checkBox_sign.setChecked(True)
        self.checkBox_exepath.setChecked(True)
        self.checkBox_netactiuvity.setChecked(True)

        self._network_activity_cache = list()

        if hasattr(self, "button_debug"):
            self.button_debug.clicked.connect(lambda: self.debug("debug"))

        self.tabWidget.setTabText(0, "Scan")
        self.tabWidget.setTabText(1, "Manually")

        self.button_add.clicked.connect(self._on_button_add)

    @staticmethod
    def _get_full_path_of_proc(proc):
        try:
            return psutil.Process(proc.pid).exe()
        except Exception:
            return proc.name()

    def _get_printable_proc_information(self, proc, netconnection_model):
        if self.checkBox_exepath.isChecked():
            full_path = self._get_full_path_of_proc(proc)
        else:
            full_path = ""

        network_activity_str = None

        if netconnection_model:
            net_connection_entity = netconnection_model.get(proc.pid)
        else:
            net_connection_entity = None
            network_activity_str = ""

        if net_connection_entity:
            try:
                r_ip = net_connection_entity.raddr.ip.__str__()
            except Exception:
                r_ip = "?"

            try:
                r_port = net_connection_entity.raddr.port.__str__()
            except Exception:
                r_port = "?"

            proto = "TCP" if socket.SOCK_STREAM else "UDP"

            network_activity_str = "({}) {}:{} -> {}:{}".format(
                proto,
                net_connection_entity.laddr.ip,
                net_connection_entity.laddr.port,
                r_ip,
                r_port,
            )

            print(net_connection_entity)

            self._update_network_cache(proc)

        if self.checkBox_sign.isChecked():
            status, err = check_sign(full_path)
            if err:
                sign_check_str = err
            elif status:
                sign_check_str = "True"
            else:
                sign_check_str = "Unknown"
        else:
            sign_check_str = ""

        return full_path, network_activity_str, sign_check_str

    def _update_network_cache(self, proc):
        t = (proc.pid, proc.name())
        if t in self._network_activity_cache:
            self._network_activity_cache.remove(t)
        self._network_activity_cache.append(t)

        self.table_network_activity.setRowCount(len(self._network_activity_cache))
        for i, t in enumerate(self._network_activity_cache):
            self.table_network_activity.setItem(i, 0, QTableWidgetItem(str(t[0])))
            self.table_network_activity.setItem(i, 1, QTableWidgetItem(str(t[1])))

    def _on_button_start_scan(self):
        self._proc_scanner.scan()

        if self.checkBox_netactiuvity.isChecked():
            self._netconnection_worker.scan()
            netconnection_model = self._netconnection_worker.get_model()
        else:
            netconnection_model = None

        self.main_table.setRowCount(len(self._proc_scanner.procs()))

        for i, proc in enumerate(self._proc_scanner.procs()):
            (
                full_path,
                network_activity,
                sign_check_str,
            ) = self._get_printable_proc_information(proc, netconnection_model)

            # print("Add to printable table", full_path, network_activity)

            self._put_to_table(
                self.main_table,
                (proc.pid, full_path, network_activity, sign_check_str),
                i,
            )

    def _put_to_table(self, table, printable_entity, row_num):
        if self.checkBox_pid.isChecked():
            table.setItem(row_num, 0, QTableWidgetItem(str(printable_entity[0])))
        else:
            table.setItem(row_num, 0, QTableWidgetItem(""))

        table.setItem(row_num, 1, QTableWidgetItem(str(printable_entity[1])))
        table.setItem(row_num, 2, QTableWidgetItem(str(printable_entity[2])))
        table.setItem(row_num, 3, QTableWidgetItem(str(printable_entity[3])))

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
        self.main_table_2.setRowCount(rows + len(result.keys()))

        for i, (section_addr, attrs) in enumerate(result.items()):
            self.main_table_2.setItem(rows + i, 0, QTableWidgetItem(path_proc))
            self.main_table_2.setItem(rows + i, 1, QTableWidgetItem(hex(section_addr)))
            self.main_table_2.setItem(rows + i, 2, QTableWidgetItem(attrs))

    def debug(self, msg):
        debug_panel = getattr(self, "debug_panel", None)
        if debug_panel:
            self.debug_panel.setPlainText(self.debug_panel.toPlainText() + "\n" + msg)

    def _on_button_clear(self):
        self.main_table_2.setRowCount(0)
