import json
import time

from workers.netstat_worker import NetstatWorker


def _load_settings():
    with open("settings.json", "r") as f:
        return json.load(f)


if __name__ == "__main__":
    settings = _load_settings()

    # worker = SignToolWorker(settings["sign_tool_worker"])
    # worker.verify("test/test_executable")

    worker = NetstatWorker(settings["netsat_worker"])
    worker.start_scan()

    for i in range(10):
        time.sleep(1)
        model = worker.get_current_model()

        print("model:")
        for model_entity in model:
            print(model_entity)

    worker.stop_scan()
