import shutil
import sys
import threading
from capstone import *
import difflib
import pefile
from PyQt5.QtCore import QObject, pyqtSignal
import os
from workers.pe_worker import analyze_section

differ = difflib.Differ()


__path_exe = None
__path_dump = None


def get_last_path_exe():
    return __path_exe


def get_last_path_dump():
    return __path_dump


class PDBRunner(threading.Thread, QObject):

    signal_ready = pyqtSignal(object)

    def __init__(self, pid, path_exe):
        threading.Thread.__init__(self)
        QObject.__init__(self)

        self.pid = pid
        self.path_exe = path_exe
        self.p = None

    def __get_diff(self, pe_exe, pe_dump) -> dict:
        print("Creating 2 pe-objects")
        print("Sections in object 1: {}".format(len(pe_exe.sections)))
        print("Sections in object 2: {}".format(len(pe_dump.sections)))

        res = {}

        for i, (section1, section2) in enumerate(zip(pe_exe.sections, pe_dump.sections)):
            data_in_disk = section1.get_data()
            data_in_dump = section2.get_data()

            diff = set(data_in_dump) - set(data_in_disk)
            d = len(diff) / len(data_in_dump)

            res[section2.Misc_PhysicalAddress] = (d, analyze_section(section2))

        return res

    def run(self) -> None:
        path_bdb = "./../exe/pdb" if sys.platform == "linux" else "..\\exe\\pd64.exe"
        cmd = path_bdb + " -pid " + str(self.pid)

        try:
            olddir = os.getcwd()
            if not os.path.exists(str(self.pid)):
                os.mkdir(str(self.pid))
            os.chdir(str(self.pid))
            os.system(cmd)
            os.chdir(olddir)

            for file in os.listdir(str(self.pid)):
                if file[-4:] == ".exe":
                    path_dump = str(self.pid) + os.sep + file
                    break
            else:
                path_dump = None

            print("path_dump = ", path_dump)
            global __path_dump
            __path_dump = path_dump

            if path_dump:
                diffs = self.__get_diff(pefile.PE(self.path_exe), pefile.PE(path_dump))
            else:
                diffs = None
            self.signal_ready.emit((diffs, path_dump))
        except Exception:
            self.signal_ready.emit({})


def compare_bin(pid, path_exe):

    global __path_exe
    __path_exe = path_exe

    thr = PDBRunner(pid, path_exe)
    thr.start()

    return thr.signal_ready


def get_printable_codediff(path_exe, path_dump, section_num):
    print("get_printable_codediff", path_exe, path_dump, section_num)

    if path_dump is None:
        return ""
    if path_exe is None:
        return ""

    pe_exe = pefile.PE(path_exe)
    pe_dump = pefile.PE(path_dump)
    data_exe = pe_exe.sections[section_num].get_data()
    data_dump = pe_dump.sections[section_num].get_data()

    printable_assembler_exe = ""
    for i in md.disasm(data_exe, 0):
        printable_assembler_exe += "0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str)

    printable_assembler_dump = ""
    for i in md.disasm(data_dump, 0):
        printable_assembler_dump += "0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str)

    diff = differ.compare(printable_assembler_exe.splitlines(), printable_assembler_dump.splitlines())
    return "\n".join(diff)
