import os

from logzero import logger

from . import client, finder


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


def safely_set_oracle_path(possible_path):
    oracle_path = None

    if possible_path and client.is_oracle_dir(possible_path):
        oracle_path = possible_path
        logger.debug("Using predifined ORACLE_PATH: %s" % (oracle_path))
    else:
        (oracle_path, oracle_version) = finder.find_newest()
        logger.debug("Found ORACLE_PATH: %s [Version: %s]" % (
            oracle_path, oracle_version))
    _clean_and_add_env_path(oracle_path)
