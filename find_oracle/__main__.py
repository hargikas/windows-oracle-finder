import argparse
import datetime
import os
import pprint

import find_oracle


def demo():
    pp = pprint.PrettyPrinter(compact=True)

    arch_type = None
    if find_oracle.client._is_python_64bit():
        arch_type = '64bit'
    else:
        arch_type = '32bit'
    print("Python is:", arch_type)

    # Python Newest
    print("If you call oracle_path, version = find_oracle.find_newest(), you will get the following result:")
    oracle_path, version = find_oracle.find_newest()
    print("\tOracle Path:", oracle_path)
    print("\tOracle Version:", version)

    # Internal Data
    print("\nInternal Data:")
    pp.pprint(find_oracle.cached_installations())

    # Path test
    find_oracle.safely_set_oracle_path(None)
    print("\nThe Path would be transformed to:")
    print(os.environ['PATH'])


def main():
    parser = argparse.ArgumentParser(
        description='A small package for windows machines to find where the installation of oracle client resides.')
    parser.add_argument('--refresh', action='store_true',
                        help='Refresh the internal cache')
    args = parser.parse_args()

    if args.refresh:
        print("lala")
        td = datetime.timedelta(seconds=-1)
        find_oracle.cached_installations(
            modified_cache_td=td, accessed_cache_td=td)
    demo()


if __name__ == "__main__":
    main()
