import copy
import subprocess
import threading
import time

from utils import Logger


class NetstatWorker:
    def __init__(self, settings):
        self._cmd = settings["cmd_format"]
        self.thr = None
        self.p = None

        self.__logger = Logger(self.__class__.__name__)

        self.__logger.debug(
            "Init %s with settings: %s", self.__class__.__name__, settings
        )

    def start_scan(self):
        self.__logger.debug("Start scanning with netstat")

        self.p = subprocess.Popen(
            self._cmd.split(" "), stdout=subprocess.PIPE, shell=True
        )
        self.thr = NetstatReader(self.p)
        self.thr.start()

    def stop_scan(self):
        if self.p:
            self.thr.stop()
            self.p.kill()

    def get_current_model(self):
        return self.thr.model


class NetstatReader(threading.Thread):
    def __init__(self, p):
        threading.Thread.__init__(self)

        self.logger = Logger(self.__class__.name)

        self.p = p

        self.run_flag = True
        self.model = []

    def stop(self):
        self.run_flag = False

    def run(self) -> None:
        while self.run_flag:
            time.sleep(0.5)

            self.logger.debug("Wake up")

            try:
                line = self.p.stdout.readline()
                self.logger.debug("Read from netstat: %s", str(line))
            except Exception as err:
                self.logger.error("Error while reading from pipe: %s", err)
                continue

            if not line:
                self.logger.warning("Empty line")
                continue

            try:
                line = self._preprocess_line(line)
            except Exception as err:
                self.logger.error(err)
                continue

            self.logger.debug("Line after preprocess: %s", str(line))

            try:
                self.logger.debug("Adding to model '%s'", str(line))
                self.model.append(
                    {
                        "proto": line[0],
                        "local_addr": line[1],
                        "foreign_addr": line[2],
                        "state": line[3],
                        "pid": line[4],
                    }
                )
            except Exception as err:
                self.logger.error(
                    "Error while adding to model '%s' : %s", str(line), err
                )

    def _preprocess_line(self, line):
        try:
            line = line.decode("utf-8")
        except Exception as err:
            self.logger.error("Error while decoding line '%s': %s", str(line), err)
            raise err

        line = line.replace("\n", "").replace("\r", "")
        line = line.split(" ")
        line = [i for i in line if i]

        return line
