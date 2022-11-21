from sign_tool_worker import SignToolWorker
import json


def _load_settings():
    with open("settings.json", "r") as f:
        return json.load(f)


if __name__ == "__main__":
    settings = _load_settings()

    worker = SignToolWorker(settings["sign_tool_worker"])
    worker.verify("test/test_executable")
