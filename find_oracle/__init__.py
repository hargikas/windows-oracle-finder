__VERSION__ = '2.0'

import datetime
import functools
import getpass
import hashlib
import hmac
import io
import os
import pickle
import pickletools
import platform
import struct
import tempfile

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


class CachedOracleInstallations(object):
    def __init__(self):
        self.modified_td = datetime.timedelta(days=2)
        self.accessed_td = datetime.timedelta(hours=8)
        self.secret = bytes(getpass.getuser(), 'utf-8')
        self.filename = os.path.join(
            tempfile.gettempdir(), 'oracle_installations_cache.pkl')

    def _load_data(self):
        valid_file = False
        now = datetime.datetime.utcnow()
        try:
            with io.open(self.filename, 'rb') as f_obj:
                self.cache = pickle.load(f_obj)

            signing = self._sign_data()

            if hmac.compare_digest(signing, self.cache['signed']):
                valid_file = True
        except BaseException:
            valid_file = False

        if not valid_file:
            self.cache = {'modified': now, 'accessed': now,
                          'data': None, 'signed': b''}

    def _save_data(self):
        try:
            self.cache['signed'] = self._sign_data()

            # Try to make a shorter file
            data = pickle.dumps(self.cache, protocol=pickle.HIGHEST_PROTOCOL)
            opt_data = pickletools.optimize(data)

            # Write Everything
            with io.open(self.filename, 'wb') as f_obj:
                f_obj.write(opt_data)
        except BaseException:
            pass

    def _sign_data(self):
        # Sign the data
        sign = hmac.new(self.secret, msg=None, digestmod=hashlib.sha256)

        keys = [x for x in self.cache.keys() if x != 'signed']
        keys.sort()

        for key in keys:
            part = self.cache[key]
            message = str(part).encode("utf-8")
            sign.update(message)
        
        # For updating the version of the pickle
        sign.update(__VERSION__.encode("utf-8"))

        return sign.hexdigest()

    def get_installations(self):
        result = None
        self._load_data()
        now = datetime.datetime.utcnow()

        if self.cache['data']:
            td_mod = now - self.cache['modified']
            td_acc = now - self.cache['accessed']
            if (td_mod < self.modified_td) or (td_acc < self.accessed_td):
                self.cache['accessed'] = now
                result = self.cache['data']

        if not result:
            self.cache['data'] = find_installations()
            self.cache['modified'] = now
            self.cache['accessed'] = now
            result = self.cache['data']

        self._save_data()
        return result


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


def _clean_and_add_env_path(add_path):
    cleaned_path = []
    # Clean the already defined path
    for c_path in os.environ['PATH'].split(';'):
        if (c_path and (c_path.casefold() not in [x.casefold() for x in cleaned_path])):
            cleaned_path.append(c_path)

    # Add the new paths in the start of the path
    if add_path:
        add_path_case = add_path.casefold()
        for c_path in cleaned_path[:]:
            if add_path_case == c_path.casefold():
                cleaned_path.remove(c_path)
        cleaned_path.insert(0, add_path)

    os.environ['PATH'] = ";".join(cleaned_path)


def find_installations():
    logger.warning("Searching for Oracle Installations...")
    result = {
        '32bit': [],
        '64bit': []
    }
    cnt = 0
    pattern = ORACLE_DLL.casefold()
    for drive in _get_local_drives():
        for root, dirs, files in os.walk(drive):
            for c_file in files:
                if c_file.casefold() == pattern:
                    file_path = os.path.join(root, c_file)
                    
                    if _is_32bit(file_path):
                        output = result['32bit']
                    else:
                        output = result['64bit']
                    cnt += 1
                    file_path = os.path.join(root, c_file)
                    deep = file_path.count(os.sep)
                    output.append((_get_version_number(file_path), (deep, cnt), file_path))
                    dirs.clear()
                    break

    # Order them by newest first
    result['32bit'].sort(key=lambda x: (x[0][0], x[0][1], x[0][2], x[0][3], -x[1][0], -x[1][1]), reverse=True)
    result['64bit'].sort(key=lambda x: (x[0][0], x[0][1], x[0][2], x[0][3], -x[1][0], -x[1][1]), reverse=True)
    return result


@functools.lru_cache(maxsize=None)
def cached_installations():
    cache = CachedOracleInstallations()
    result = cache.get_installations()
    return result


def find_newest():
    installations = cached_installations()

    if _is_python_64bit():
        dll_installations = installations['64bit']
    else:
        dll_installations = installations['32bit']

    newest_dll = dll_installations[0][2]
    return (os.path.dirname(newest_dll), _get_version_string(newest_dll))


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


def safely_set_oracle_path(possible_path):
    oracle_path = None

    if possible_path and is_oracle_dir(possible_path):
        oracle_path = possible_path
        logger.debug("Using predifined ORACLE_PATH: %s" % (oracle_path))
    else:
        (oracle_path, oracle_version) = find_newest()
        logger.debug("Found ORACLE_PATH: %s [Version: %s]" % (
            oracle_path, oracle_version))
    _clean_and_add_env_path(oracle_path)


if __name__ == "__main__":
    print(cached_installations())
    print(find_newest())
