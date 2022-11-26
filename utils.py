import logging
import os.path


class Logger(logging.Logger):
    def __init__(self, name):
        logging.Logger.__init__(self, name)

        self._log_path_dir = "logs"
        self._log_file_name = "all.log"

        self._ensure_dir()

        handler = logging.FileHandler(self._log_path_dir + "/" + self._log_file_name)
        handler.setFormatter(logging.Formatter("[%(name)s] %(message)s"))
        self.addHandler(handler)
        self.addHandler(logging.StreamHandler())
        self.setLevel(logging.DEBUG)

    def _ensure_dir(self):
        if not os.path.exists(self._log_path_dir):
            os.mkdir(self._log_path_dir)
