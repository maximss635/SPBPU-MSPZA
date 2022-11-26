import json
import time
import sys
from workers.netstat_worker import NetstatWorker
from utils import Logger


LOGGER = Logger(__name__)


def _load_settings():
    if sys.platform == "linux":
        path_settings = "settings_linux.json"
        LOGGER.debug("Platform is linux -> path settings = %s", path_settings)
    else:
        path_settings = "settings_windows.json"
        LOGGER.debug("Platform is windows -> path settings = %s", path_settings)

    with open(path_settings, "r") as f:
        return json.load(f)


if __name__ == "__main__":
    settings = _load_settings()

    # worker = SignToolWorker(settings["sign_tool_worker"])
    # worker.verify("test/test_executable")

    worker = NetstatWorker(settings["netsat_worker"])
    worker.start_scan()

    try:
        while True:
            time.sleep(1)
            model = worker.get_current_model()

            print("model:")
            for model_entity in model:
                print(model_entity)
    except KeyboardInterrupt:
        pass

    worker.stop_scan()
