import psutil

from virus_total_api import vt_ip_url_analysis


class NetConnectionWorker:
    def __init__(self):
        self._model = {}
        self._good_ip_cache = {"127.0.0.1": True}

    def check_ip(self, ip_struct):
        if not ip_struct.raddr:
            return True

        if ip_struct.raddr.ip in self._good_ip_cache:
            return self._good_ip_cache[ip_struct.raddr.ip]

        try:
            print(f"CHECK {ip_struct.raddr.ip}")
            answ = vt_ip_url_analysis.urlReport(ip_struct.raddr.ip)
            print("ANSWER = ", answ)

            self._good_ip_cache[ip_struct.raddr.ip] = (answ[0] >= 0)

            return answ[0] >= 0
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
