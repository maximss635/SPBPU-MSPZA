import copy
import subprocess
import threading
import time

from utils import Logger


class NetstatWorker:
    def __init__(self, settings):
        self.settings = copy.deepcopy(settings)
        self.thr = None
        self.p = None

        self.__logger = Logger(self.__class__.__name__)

        self.__logger.debug(
            "Init %s with settings: %s", self.__class__.__name__, settings
        )

    def start_scan(self):
        cmd = self.settings["cmd_format"]

        self.__logger.debug("Start scanning with command: %s", cmd)
        self.p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

        self.thr = NetstatReader(self.p, self.settings["header"])
        self.thr.start()

    def stop_scan(self):
        if self.p:
            self.thr.stop()
            self.p.kill()

    def get_current_model(self):
        return self.thr.model


class NetstatReader(threading.Thread):
    def __init__(self, p, head_list):
        threading.Thread.__init__(self)

        self.logger = Logger(self.__class__.__name__)

        self.p = p

        self.run_flag = True
        self.model = []
        self.head_list = head_list

        self.logger.debug("Init %s", self.__class__.__name__)

    def stop(self):
        self.logger.debug("Stopping thread")
        self.run_flag = False

    def run(self) -> None:
        self.logger.debug("Running thread")

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
                new_entity = {title: line[i] for i, title in enumerate(self.head_list)}

                new_entity = self._additional_entity_preprocess(new_entity)

                self.logger.debug("Adding to model entity '%s'", str(new_entity))
                self.model.append(new_entity)
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

    def _additional_entity_preprocess(self, entity):
        self.logger.debug("Additional entity preprocess")

        if 'pid' in entity:
            if '/' in entity["pid"]:
                old = entity["pid"]
                entity['pid'], entity['programm_name'] = entity["pid"].split('/')
                self.logger.debug("%s' -> %s, %s", old, entity['pid'], entity['programm_name'])

        return entity
