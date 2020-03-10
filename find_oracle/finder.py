import functools
import os
import platform

from logzero import logger

from . import cache, client


def find_installations():
    logger.warning("Searching for Oracle Installations...")
    result = {
        '32bit': [],
        '64bit': []
    }
    cnt = 0
    pattern = client.ORACLE_DLL.casefold()
    for drive in client._get_local_drives():
        for root, dirs, files in os.walk(drive):
            for c_file in files:
                if c_file.casefold() == pattern:
                    file_path = os.path.join(root, c_file)

                    if client._is_32bit(file_path):
                        output = result['32bit']
                    else:
                        output = result['64bit']
                    cnt += 1
                    file_path = os.path.join(root, c_file)
                    deep = file_path.count(os.sep)
                    output.append((client._get_version_number(
                        file_path), (deep, cnt), file_path))
                    dirs.clear()
                    break

    # Order them by newest first
    result['32bit'].sort(key=lambda x: (
        x[0][0], x[0][1], x[0][2], x[0][3], -x[1][0], -x[1][1]), reverse=True)
    result['64bit'].sort(key=lambda x: (
        x[0][0], x[0][1], x[0][2], x[0][3], -x[1][0], -x[1][1]), reverse=True)
    return result


@functools.lru_cache(maxsize=None)
def cached_installations(modified_cache_td=None, accessed_cache_td=None):
    cache_obj = cache.OracleInstallations(
        modified_td=modified_cache_td, accessed_td=accessed_cache_td)
    result = cache_obj.get_installations()
    return result


def find_newest():
    installations = cached_installations()

    arch_type = None
    if client._is_python_64bit():
        arch_type = '64bit'
    else:
        arch_type = '32bit'
    dll_installations = installations[arch_type]

    if dll_installations:
        newest_dll = dll_installations[0][2]
        return (os.path.dirname(newest_dll), client._get_version_string(newest_dll))

    logger.error(
        "Couldn't find any %s oracle installations in this system." % (arch_type))
    return (None, None)
