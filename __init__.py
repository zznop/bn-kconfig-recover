"""
Binary Ninja plugin for recovering kernel build configuration settings using BNIL
"""

import argparse
from binaryninja import BinaryViewType
from kconfig import KConfigRecover, print_kconfig


def parse_args() -> argparse.Namespace:
    """Parses command line arguments.

    Returns:
      Parsed command line arguments.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument(
        'bndb', help='File path to kernel ELF or Binary Ninja database')
    return parser.parse_args()


def main():
    """Parse command line arguments and run app.
    """

    args = parse_args()

    bv = BinaryViewType.get_view_of_file(args.bndb)
    bv.update_analysis_and_wait()

    recover = KConfigRecover(bv)
    config = recover.do()
    print_kconfig(config)


if __name__ == '__main__':
    main()