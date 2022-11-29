import sys

import pefile
from reactivex import create
import functools
import subprocess
import os



def get_diff(path_disk, path_dump) -> list:

    pe1 = pefile.PE(path_disk)
    pe2 = pefile.PE(path_dump)

    print("Creating 2 pe-objects")
    print("Sections in object 1: {}".format(len(pe1.sections)))
    print("Sections in object 2: {}".format(len(pe2.sections)))

    res = []

    for i, (section1, section2) in enumerate(zip(pe1.sections, pe2.sections)):
        data_in_disk = section1.get_data()
        data_in_dump = section2.get_data()

        diff = set(data_in_dump) - set(data_in_disk)
        d = len(diff) / len(data_in_dump)

        res.append(d)

    return res


def on_dump_ready(pid, path_exe):

    # Вот тут получил путь до файла с расширением .exe в папке с pid процессом и передай в get_diff

    path_dump = None
    for file in os.listdir(str(pid)):
        if file[-4:] == ".exe":
            path_dump = file
            break

    diffs = get_diff(path_disk=path_exe, path_dump=path_dump)


def dump_process(observer, pid):
    print("start dump_process")

    if not os.path.isdir(str(pid)):
        os.mkdir(str(pid))

    old_dir = os.getcwd()
    os.chdir(str(pid))

    path_pd64 = "exe/pdb64" if sys.platform == "linux" else "exe/pdb64.exe"
    cmd = path_pd64 + " -pid " + str(pid)
    subprocess.run(cmd)

    os.chdir(old_dir)

    observer.on_completed()


def compare_bin(pid, path_exe):
    print("compare_bin", pid, path_exe)

    dump_process_wrapper = functools.partial(dump_process, pid=pid)

    dump_observer = create(dump_process_wrapper)
    dump_observer.subscribe(
        on_completed=lambda: on_dump_ready(pid, path_exe),
    )


if __name__ == '__main__':
    compare_bin(8012)
