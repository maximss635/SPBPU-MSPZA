from workers import codediff
import socket
import threading

import psutil
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem, QWidget
from PyQt5.QtCore import Qt

from gui.ask_process_window import AskProcessWindow
from gui.main_window_ui import Ui_MainWindow
from workers import capa_worker
from workers.net_connection_worker import NetConnectionWorker
from workers.pe_worker import analyze_pe_file, check_packer
from workers.scanner import Scanner
from workers.sign_check import check_sign
import time


def _capa_parsing(capa_lines):
    """
    Парсинг вывод утилиты capa
    :param capa_lines: Строки для парсинга
    :rtype capa_lines: list[str]
    :return: 6 блоков строчек
    :rtype: tuple[list[str]]
    """
    def get_start_index(lines, line_template):
        for _i, line in enumerate(lines):
            if line_template in line:
                while '---------' not in lines[_i]:
                    _i = _i + 1
                return 1 + _i
        return -1

    index_1 = get_start_index(capa_lines, "ATT&CK Tactic")
    index_2 = get_start_index(capa_lines, "MBC Objective")
    index_3 = get_start_index(capa_lines, "CAPABILITY")

    def get_stop_index(lines, start_index):
        for _j, line in enumerate(lines[start_index:]):
            if '------------' in line:
                return _j + start_index - 1

        return -1

    index_1_stop = get_stop_index(capa_lines, index_1)
    index_2_stop = get_stop_index(capa_lines, index_2)
    index_3_stop = get_stop_index(capa_lines, index_3)

    output_1_2 = capa_lines[index_1:index_1_stop + 1]
    output_3_4 = capa_lines[index_2:index_2_stop + 1]
    output_5_6 = capa_lines[index_3:index_3_stop + 1]

    print(output_1_2)
    print(output_3_4)
    print(output_5_6)

    output_1, output_2 = [], []
    for line in output_1_2:
        if line.startswith("|"):
            line = line[1:]
        output_1.append(line.split('|')[0])
        output_2.append(line.split('|')[1])

    output_3, output_4 = [], []
    for line in output_3_4:
        if line.startswith("|"):
            line = line[1:]
        output_3.append(line.split('|')[0])
        output_4.append(line.split('|')[1])

    output_5, output_6 = [], []
    for line in output_5_6:
        if line.startswith("|"):
            line = line[1:]
        output_5.append(line.split('|')[0])
        output_6.append(line.split('|')[1])

    return output_1, output_2, output_3, output_4, output_5, output_6


class MainWindow(Ui_MainWindow, QMainWindow):
    def __init__(self):
        Ui_MainWindow.__init__(self)
        QMainWindow.__init__(self)

        self.setupUi(self)

        # Pretty gui
        self.setCentralWidget(self.tabWidget)

        self.button_start_scan.clicked.connect(self._on_button_start_scan)
        self.button_stop_scan.clicked.connect(self._on_button_stop_scan)
        self.button_capa_analyze.clicked.connect(self._on_button_capa_analyze)
        self.button_capa_analyze_2.clicked.connect(self._on_button_get_codediff)

        self.checkBox_pid.setChecked(True)
        self.checkBox_sign.setChecked(False)
        self.checkBox_exepath.setChecked(True)
        self.checkBox_netactiuvity.setChecked(True)
        self.checkBox_packing.setChecked(False)

        if hasattr(self, "button_debug"):
            self.button_debug.clicked.connect(lambda: self.debug("debug"))

        self.capa_table.setColumnWidth(0, 500)
        self.capa_table.setColumnWidth(1, 500)

        self.table_codediff.setColumnWidth(0, 300)
        self.table_codediff.setColumnWidth(1, 300)
        self.table_codediff.setColumnWidth(2, 300)

        self.capa_titles = [
            "ATT&CK Tactic",
            "ATT&CK Technique",
            "MBC Objective",
            "MBC Behavior",
            "CAPABILITY",
            "NAMESPACE"
        ]

        self.capa_table.setItem(0, 0, QTableWidgetItem(self.capa_titles[0]))
        self.capa_table.setItem(0, 1, QTableWidgetItem(self.capa_titles[1]))
        self.capa_table.setItem(2, 0, QTableWidgetItem(self.capa_titles[2]))
        self.capa_table.setItem(2, 1, QTableWidgetItem(self.capa_titles[3]))
        self.capa_table.setItem(4, 0, QTableWidgetItem(self.capa_titles[4]))
        self.capa_table.setItem(4, 1, QTableWidgetItem(self.capa_titles[5]))

    def _create_thread(self):
        self._thr = ThreadScanner()
        self._thr.signal_new_item.connect(self.slot_new_items)
        # self._thr.signal_new_cache.connect(self.slot_update_cache_table)

    def slot_new_items(self, args):
        entity, row = args
        self._put_to_table(self.main_table, entity, row)

    def _on_button_capa_analyze(self):
        self.capa_table.setItem(1, 0, QTableWidgetItem("Analyzing..."))
        self.capa_table.setItem(1, 1, QTableWidgetItem("Analyzing..."))
        self.capa_table.setItem(3, 0, QTableWidgetItem("Analyzing..."))
        self.capa_table.setItem(3, 1, QTableWidgetItem("Analyzing..."))
        self.capa_table.setItem(5, 0, QTableWidgetItem("Analyzing..."))
        self.capa_table.setItem(5, 1, QTableWidgetItem("Analyzing..."))

        signal = capa_worker.run_capa(self.textEdit.toPlainText())
        signal.connect(self._on_capa_result)

    def _on_capa_result(self, args):
        print("_on_capa_result", args)

        path_out, _ = args

        with open(path_out, "r") as f:
            lines = f.readlines()

        # os.remove(path_out)
        outputs = _capa_parsing(lines)

        i__ = [1, 1, 3, 3, 5, 5]
        j__ = [0, 1, 0, 1, 0, 1]

        for i, j, output in zip(i__, j__, outputs):
            new_output = []
            for line in output:
                new_output.append(line.replace("\x1b[34m", "").replace("\x1b[0m", ""))
            self.capa_table.setItem(i, j, QTableWidgetItem("\n".join(new_output) if new_output else "-"))

    def _on_button_start_scan(self):
        need_model = (
            self.checkBox_pid.isChecked(),
            self.checkBox_exepath.isChecked(),
            self.checkBox_netactiuvity.isChecked(),
            self.checkBox_sign.isChecked(),
            self.checkBox_packing.isChecked(),
            self.checkBox_sections.isChecked(),
        )

        for i, need_flag in enumerate(need_model):
            self.main_table.setColumnHidden(i, not need_flag)

        self._create_thread()

        self.main_table.setRowCount(0)

        self._thr.start(*need_model)

    def _put_to_table(self, table, printable_entity, row_num):
        print("put_to_table", printable_entity, row_num)



        reds_count = 0
        reds = []

        table.setRowCount(table.rowCount() + 1)

        if self.checkBox_pid.isChecked():
            table.setItem(row_num, 0, QTableWidgetItem(str(printable_entity[0])))
        else:
            table.setItem(row_num, 0, QTableWidgetItem(""))

        table.setItem(row_num, 1, QTableWidgetItem(str(printable_entity[1])))

        net_activity = printable_entity[2]
        table.setItem(row_num, 2, QTableWidgetItem(str(net_activity)))
        if net_activity:
            table.item(row_num, 2).setBackground(Qt.red)
        else:
            table.item(row_num, 2).setBackground(Qt.green)

        sign_check = str(printable_entity[3])
        table.setItem(row_num, 3, QTableWidgetItem(sign_check))
        if sign_check == "True":
            table.item(row_num, 3).setBackground(Qt.green)
        else:
            table.item(row_num, 3).setBackground(Qt.red)

        packing = str(printable_entity[4])
        table.setItem(row_num, 4, QTableWidgetItem(packing))
        if packing == "":
            table.item(row_num, 4).setBackground(Qt.green)
        else:
            table.item(row_num, 4).setBackground(Qt.red)

        attrs = str(printable_entity[5])
        table.setItem(row_num, 5, QTableWidgetItem(attrs))

        have_wx = printable_entity[6]
        if have_wx or not attrs:
            table.item(row_num, 5).setBackground(Qt.red)
            reds_count = reds_count + 1

            reds.append("Have WX")
        else:
            table.item(row_num, 5).setBackground(Qt.green)

        print("reds = ", reds)

        if reds_count >= 2:
            table.item(row_num, 0).setBackground(Qt.red)
            table.item(row_num, 1).setBackground(Qt.red)
        else:
            table.item(row_num, 0).setBackground(Qt.green)
            table.item(row_num, 1).setBackground(Qt.green)

        if self.checkBox_capa.isChecked() and have_wx:
            def _on_capa_ready(args):
                print("_on_capa_result", args)

                path, row = args

                with open(path, "r") as f:
                    lines = f.readlines()

                # os.remove(path)
                outputs = _capa_parsing(lines)
                capa_output_to_table = str(len(outputs[-1]) + len(outputs[-2]))
                table.item(row, 5, QTableWidgetItem(capa_output_to_table))

            signal = capa_worker.run_capa(str(printable_entity[1]))
            signal.connect(_on_capa_ready)
            table.setItem(row_num, 5, QTableWidgetItem("Analyze..."))

    def _on_button_stop_scan(self):
        self.debug("_on_button_stop_scan")
        self._thr.stop()

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

    def _on_button_get_codediff(self):
        print("_on_button_get_codediff")
        path_exe = self.textEdit_2.toPlainText()

        scanner = Scanner()
        scanner.scan()
        for p in scanner.procs():
            if ThreadScanner.get_full_path_of_proc(p) == path_exe:
                pid = p.pid
                break
        else:
            pid = None

        if not pid:
            return

        signal = codediff.compare_bin(pid=pid, path_exe=path_exe)
        signal.connect(self._on_codediff_ready)

        self.table_codediff.setRowCount(1)
        self.table_codediff.setItem(0, 0, QTableWidgetItem("Analyzing..."))
        self.table_codediff.setItem(0, 1, QTableWidgetItem("Analyzing..."))
        self.table_codediff.setItem(0, 1, QTableWidgetItem("Analyzing..."))

    def _on_codediff_ready(self, diffs):
        print("_on_codediff_ready", diffs)

        self.table_codediff.setRowCount(len(diffs.keys()))

        for i, (addr, (attrs, diff)) in enumerate(diffs.items()):
            self.table_codediff.setItem(i, 0, QTableWidgetItem(hex(addr)))
            self.table_codediff.setItem(i, 1, QTableWidgetItem(str(attrs)))
            self.table_codediff.setItem(i, 2, QTableWidgetItem(str(diff)))


class ThreadScanner(threading.Thread, QObject):
    signal_new_item = pyqtSignal(object)
    signal_new_cache = pyqtSignal(object)

    def __init__(self):
        threading.Thread.__init__(self)
        QObject.__init__(self)

        self._netconnection_worker = NetConnectionWorker()
        self._proc_scanner = Scanner()

        self._network_activity_cache = list()

        self.flag_run = False

    def start(self, need_pid, need_path, need_networkactivity, need_sign, need_packing, need_sections) -> None:
        self.need_pid = need_pid
        self.need_path = need_path
        self.need_sign = need_sign
        self.need_networkactivity = need_networkactivity
        self.need_packing = need_packing
        self.need_sections = need_sections

        self.flag_run = True

        threading.Thread.start(self)

    def stop(self):
        self.flag_run = False

    def _put_to_table(self, entity, row_num):
        self._last_data = (entity, row_num)
        self.signal_new_item.emit((entity, row_num))

    def run(self):

        self._proc_scanner.scan()

        if self.need_networkactivity:
            self._netconnection_worker.scan()
            netconnection_model = self._netconnection_worker.get_model()
        else:
            netconnection_model = None

        for i, proc in enumerate(self._proc_scanner.procs()):
            if not self.flag_run:
                break

            (
                full_path,
                network_activity,
                sign_check_str,
                packed_str,
                attrs_str,
                have_wx
            ) = self._get_printable_proc_information(proc, netconnection_model)
            print("Add to printable table", i)

            self._put_to_table(
                (proc.pid, full_path, network_activity, sign_check_str, packed_str, attrs_str, have_wx), i
            )

    def _get_printable_proc_information(self, proc, netconnection_model):
        if self.need_path:
            full_path = self.get_full_path_of_proc(proc)
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

        if self.need_sign:
            status, err = check_sign(full_path)
            if err:
                sign_check_str = err
            elif status:
                sign_check_str = "True"
            else:
                sign_check_str = "Unknown"
        else:
            sign_check_str = ""

        if self.need_packing:
            is_packed_str = check_packer(full_path)
        else:
            is_packed_str = ""

        attrs_str = ""
        have_wx = False
        if self.need_sections:
            sections = analyze_pe_file(full_path)
            attrs_str = ""
            for addr, attrs in sections.items():
                attrs_str += "{}: {}, ".format(hex(addr), attrs)
                if "WX" in attrs:
                    have_wx = True
            attrs_str = attrs_str[:-2]

        return full_path, network_activity_str, sign_check_str, is_packed_str, attrs_str, have_wx

    @staticmethod
    def get_full_path_of_proc(proc):
        try:
            return psutil.Process(proc.pid).exe()
        except Exception:
            return proc.name()

    def _update_network_cache(self, proc):
        t = (proc.pid, proc.name())
        if t in self._network_activity_cache:
            self._network_activity_cache.remove(t)
        self._network_activity_cache.append(t)

        self.signal_new_cache.emit(self._network_activity_cache)
