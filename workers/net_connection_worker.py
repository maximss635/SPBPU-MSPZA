import psutil
from workers import virus_total_api

class NetConnectionWorker:
    def __init__(self):
        self._model = {}
        self._good_ip_cache = {"127.0.0.1": True}

    def check_ip(self, ip_struct):
        if not ip_struct.raddr:
            return True, None

        if ip_struct.raddr.ip in self._good_ip_cache:
            score = self._good_ip_cache[ip_struct.raddr.ip]
            return score == 0, score

        if ip_struct.raddr.ip.startswith("192.168"):
            return True

        try:
            print(f"CHECK {ip_struct.raddr.ip}")
            score = virus_total_api.check_ip(ip_struct.raddr.ip)
            print("score = ", score)

            self._good_ip_cache[ip_struct.raddr.ip] = score

            return score == 0, score
        except Exception as err:
            print("ERROR {}".format(err))
            return True

    def scan(self):
        for i in psutil.net_connections(kind='inet'):
            self._model[i.pid] = i

    def get_model(self):
        return self._model


if __name__ == '__main__':
    worker = NetConnectionWorker()
    worker.scan()
    print(worker.get_model())
