import psutil


class NetConnectionWorker:
    def __init__(self):
        self._model = {}

    def scan(self):
        for i in psutil.net_connections(kind='inet'):
            self._model[i.pid] = i

    def get_model(self):
        return self._model


if __name__ == '__main__':
    worker = NetConnectionWorker()
    worker.scan()
    print(worker.get_model())
