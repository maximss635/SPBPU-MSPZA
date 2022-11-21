import subprocess

from utils import Logger


class SignToolWorker:
    _PATH_EXECUTABLE = "signtool"

    def __init__(self, settings):
        self.__logger = Logger()
        self._cmd_format = settings["cmd_format"]

        self.__logger.debug("Init %s with settings: %s", self.__class__.__name__, settings)

    def verify(self, filepath_to_verify):
        self.__logger.debug("Verify: %s", filepath_to_verify)

        cmd = self._cmd_format.replace("[filename]", filepath_to_verify).split(" ")
        self.__logger.debug("cmd = {}".format(cmd))

        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            self._handle_process(p)

    def _handle_process(self, p):
        self.__logger.debug("p = {}".format(p))

        out_log = p.stdout.read()
        err_log = p.stderr.read()

        self.__logger.debug("out_log = {}".format(out_log))
        self.__logger.debug("err_log = {}".format(err_log))
