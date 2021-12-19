"""
Binary Ninja plugin for recovering kernel build configuration settings using BNIL
"""

import argparse
import logging
from binaryninja import BinaryViewType
from kconfig import KConfigRecover, save_kconfig


def parse_args() -> argparse.Namespace:
    """Parses command line arguments.

    Returns:
      Parsed command line arguments.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument(
        'bndb', help='File path to kernel ELF or Binary Ninja database')
    parser.add_argument(
        'kconfig', help='File path to save recovered kernel configuration')
    parser.add_argument('-d',
                        '--debug',
                        action='store_true',
                        help='Enable debug logging')
    return parser.parse_args()


def main():
    """Parse command line arguments and run app.
    """

    args = parse_args()

    logger = logging.getLogger()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logging.info(f'Opening "{args.bndb}" and getting view...')
    bv = BinaryViewType.get_view_of_file(args.bndb)
    logging.info('Running BN analysis, this may take some time...')
    #bv.reanalyze()
    bv.update_analysis_and_wait()

    recover = KConfigRecover(bv)
    config = recover.do()
    save_kconfig(config, args.kconfig)


if __name__ == '__main__':
    main()
