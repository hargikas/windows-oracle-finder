import functools
import os
import struct

import pefile
import win32api
import win32file
from logzero import logger

#
# cut-and-pasted from MSDN
#
DRIVE_TYPES = """
0 	Unknown
1 	No Root Directory
2 	Removable Disk
3 	Local Disk
4 	Network Drive
5 	Compact Disc
6 	RAM Disk
"""

ORACLE_DLL = 'oci.dll'


@functools.lru_cache(maxsize=None)
def _get_version_number(filename):
    info = win32api.GetFileVersionInfo(filename, "\\")
    ms = info['FileVersionMS']
    ls = info['FileVersionLS']
    v_numbers = [win32api.HIWORD(ms), win32api.LOWORD(
        ms), win32api.HIWORD(ls), win32api.LOWORD(ls)]
    return v_numbers


@functools.lru_cache(maxsize=None)
def _get_version_string(filename):
    v_numbers = _get_version_number(filename)
    return ".".join([str(i) for i in v_numbers])


@functools.lru_cache(maxsize=None)
def _is_32bit(filename):
    # pylint: disable=maybe-no-member
    # Machine: the architecture this binary is supposed to run on (0x014C == x86 binary and 0x8664 == x86-x64 binary)
    pe = pefile.PE(filename)
    return hex(pe.FILE_HEADER.Machine) == '0x14c'


def _is_python_64bit():
    return (struct.calcsize("P") == 8)


def _is_valid_dll(filename):
    if _is_python_64bit():
        return not _is_32bit(filename)
    else:
        return _is_32bit(filename)


def _get_logical_drives():
    result = []
    drive_types = dict((int(i), j) for (i, j) in (l.split("\t")
                                                  for l in DRIVE_TYPES.splitlines() if l))

    drives = (drive for drive in win32api.GetLogicalDriveStrings().split(
        "\000") if drive)
    for drive in drives:
        result.append((drive, drive_types[win32file.GetDriveType(drive)]))
    return result


def _get_local_drives():
    return [drive[0] for drive in _get_logical_drives() if drive[1] == 'Local Disk']


def is_oracle_dir(input_path):
    pattern = ORACLE_DLL.casefold()
    result = False

    try:
        if input_path:
            with os.scandir(path=input_path) as it:
                for entry in it:
                    if (entry.is_file() and (entry.name.casefold() == pattern)):
                        if _is_valid_dll(entry.path):
                            result = True
                            break
                        else:
                            error_msg = "Mismatch: The python is "
                            if _is_python_64bit():
                                error_msg += "64bit "
                            else:
                                error_msg += "32bit "
                            error_msg += "and the client in " + \
                                os.path.dirname(entry.path) + " is "
                            if _is_32bit(entry.path):
                                error_msg += "32bit."
                            else:
                                error_msg += "64bit."
                            logger.warning(error_msg)
    except BaseException:
        result = False

    if (input_path) and (not result):
        logger.error("There is no valid oracle in path: %s" % (input_path))

    return result
