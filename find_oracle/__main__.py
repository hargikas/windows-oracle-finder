import pprint

import find_oracle

if __name__ == "__main__":
    pp = pprint.PrettyPrinter(compact=True)

    arch_type = None
    if find_oracle.client._is_python_64bit():
        arch_type = '64bit'
    else:
        arch_type = '32bit'
    print("Python is:", arch_type)

    print("If you call oracle_path, version = find_oracle.find_newest(), you will get the following result:")
    oracle_path, version = find_oracle.find_newest()
    print("\tOracle Path:", oracle_path)
    print("\tOracle Version:", version)
    print()
    print("Internal Data:")
    pp.pprint(find_oracle.cached_installations())
