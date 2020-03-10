__PICKLE_FORMAT__ = '2.0'

import datetime
import getpass
import hashlib
import hmac
import io
import os
import pickle
import pickletools
import tempfile

from . import finder


def kwargs_safe_get(input_dict, key, default_value):
    """Helper function for managing None in keyword arguments"""
    result = input_dict.get(key, default_value)
    if result is None:
        result = default_value
    return result


class OracleInstallations(object):
    def __init__(self, *args, **kwargs):
        self.modified_td = kwargs_safe_get(
            kwargs, 'modified_td', datetime.timedelta(days=2))
        self.accessed_td = kwargs_safe_get(
            kwargs, 'accessed_td', datetime.timedelta(hours=8))
        self.secret = kwargs_safe_get(
            kwargs, 'secret', bytes(getpass.getuser(), 'utf-8'))
        self.filename = kwargs_safe_get(kwargs, 'filename', os.path.join(
            tempfile.gettempdir(), 'oracle_installations_cache.pkl'))
        print(self.modified_td)

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
        sign.update(__PICKLE_FORMAT__.encode("utf-8"))

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
            self.cache['data'] = finder.find_installations()
            self.cache['modified'] = now
            self.cache['accessed'] = now
            result = self.cache['data']

        self._save_data()
        return result
