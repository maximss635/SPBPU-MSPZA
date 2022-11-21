import subprocess
from copy import copy
from utils import Logger


class SignToolWorker:
    _PATH_EXECUTABLE = "signtool"

    def __init__(self, settings):
        self.__logger = Logger(self.__class__.__name__)
        self._cmd_format = settings["cmd_format"]

        self.__logger.debug("Init %s with settings: %s", self.__class__.__name__, settings)

    def verify(self, filepath_to_verify):
        self.__logger.debug("Verify: %s", filepath_to_verify)

        cmd = self._make_cmd(filepath_to_verify)
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            self._handle_process(p)

    def _make_cmd(self, filepath_to_verify):
        params = {"filename": filepath_to_verify}
        result = copy(self._cmd_format)

        for k, v in params.items():
            k = "[%s]" % k
            if k in result:
                result = result.replace(k, v)

        self.__logger.debug("Generated cmd: %s", result)

        return result.split(" ")

    def _handle_process(self, p):
        self.__logger.debug("p = {}".format(p))

        out_log = p.stdout.read()
        err_log = p.stderr.read()

        self.__logger.debug("out_log = {}".format(out_log))
        self.__logger.debug("err_log = {}".format(err_log))
