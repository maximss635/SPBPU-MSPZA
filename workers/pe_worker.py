import pefile
from utils import Logger


LOGGER = Logger("pe_worker")


def __analyze_section(section):
    """
    https://blog.kowalczyk.info/articles/pefileformat.html
    0x00000020	Code section
    0x00000040	Initialized data section
    0x00000080	Uninitialized data section
    0x04000000	Section cannot be cached
    0x08000000	Section is not pageable
    0x10000000	Section is shared
    0x20000000	Executable section
    0x40000000	Readable section
    0x80000000	Writable section
    """
    r, w, x = False, False, False
    if (section.Characteristics & 0x00000020) or (section.Characteristics & 0x20000000):
        x = True
    if (section.Characteristics & 0x80000000):
        w = True
    if (section.Characteristics & 0x40000000):
        r = True

    result = ""
    result += "R" if r else "-"
    result += "W" if w else "-"
    result += "X" if x else "-"

    return result


def analyze_pe_file(filepath):
    try:
        LOGGER.debug("1")
        pe = pefile.PE(filepath)

        LOGGER.debug("2")
        result_list = []
        for section in pe.sections:
            result_list.append(__analyze_section(section))

        return ",".join(result_list)
    except Exception as err:
        LOGGER.error(err)
        return ""
