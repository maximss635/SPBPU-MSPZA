import logging
import os.path


class Logger(logging.Logger):
    def __init__(self):
        logging.Logger.__init__(self, name="all_logger")

        self._log_path_dir = "logs"
        self._log_file_name = "all.logs"

        self._ensure_dir()

        self.addHandler(
            logging.FileHandler(self._log_path_dir + "/" + self._log_file_name)
        )
        self.setLevel(logging.DEBUG)

    def _ensure_dir(self):
        if not os.path.exists(self._log_path_dir):
            os.mkdir(self._log_path_dir)
