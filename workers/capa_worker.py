import os
import sys
import threading

from PyQt5.QtCore import QObject, pyqtSignal


def run_capa(path_exe):

    class CapaThread(threading.Thread, QObject):

        signal_ready = pyqtSignal(object)

        def __init__(self, path_capa, path_exe, path_out):
            threading.Thread.__init__(self)
            QObject.__init__(self)

            self.path_capa = path_capa
            self.path_exe = path_exe
            self.path_out = path_out

        def run(self) -> None:
            print("run capa")
            print("{} {} > {}".format(self.path_capa, self.path_exe, self.path_out))
            os.system("{} {} > {}".format(self.path_capa, self.path_exe, self.path_out))
            print("capc ready")

            self.signal_ready.emit(self.path_out)

    path_capa = "./exe/capa" if sys.platform == "linux" else "exe\\capa.exe"
    thr = CapaThread(path_capa, path_exe, "exe/capa_output.txt")

    thr.start()

    return thr.signal_ready
