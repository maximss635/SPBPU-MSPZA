import psutil
from utils import Logger


class Scanner:
    def __init__(self):
        self._procs = []
        self._logger = Logger(self.__class__.__name__)

        self._logger.debug("Init %s", self.__class__.__name__)

    def scan(self):
        self._logger.debug("Scanning...")

        self._procs.clear()
        for proc in psutil.process_iter():
            self._procs.append(proc)

        self._logger.debug("Scanned %d process", len(self._procs))

    def procs(self):
        return self._procs
