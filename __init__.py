"""
Binary Ninja plugin for recovering kernel build configuration settings using BNIL
"""

import argparse
import logging
from binaryninja import (BinaryViewType, BinaryView, PluginCommand,
                         SaveFileNameField, get_form_input, BackgroundTaskThread)

class RecoverKConfigBackground(BackgroundTaskThread):
    """Class for running kernel configuration recovery in background
    """

    def __init__(self, view: BinaryView, outpath: str) -> None:
        BackgroundTaskThread.__init__(self, 'Recovering Linux kernel configuration', False)
        self.outpath = outpath
        self.view = view

    def run(self):
        """Run analysis task
        """

        self.view.reanalyze()
        self.view.update_analysis_and_wait()
        kconfigr = KConfigRecover(self.view)
        config = kconfigr.recover()
        save_kconfig(config, self.outpath)
        self.progress = ""

def run_from_ui(view: BinaryView) -> None:
    """Run as a plugin under the UI

    Args:
      view: Binary view
    """

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    config_field = SaveFileNameField('Configuration Output Path')
    get_form_input([config_field], 'Kernel Configuration Recovery Options')
    outpath = 'generated.config'
    if config_field.result != '':
        outpath = config_field.result

    kconfig_task = RecoverKConfigBackground(view, outpath)
    kconfig_task.start()

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

def run_headless() -> None:
    """Parse command line arguments and run app.
    """

    args = parse_args()

    logger = logging.getLogger()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logging.info('Opening "%s" and getting view...', args.bndb)
    view = BinaryViewType.get_view_of_file(args.bndb)
    logging.info('Running BN analysis, this may take some time...')

    kconfig_task = RecoverKConfigBackground(view, args.kconfig)
    kconfig_task.start()

if __name__ == '__main__':
    from kconfig import KConfigRecover, save_kconfig
    run_headless()
else:
    from .kconfig import KConfigRecover, save_kconfig
    PluginCommand.register(
        "Recover Linux kernel config",
        "Analyze Linux kernel binary and recover kernel configuration options",
        run_from_ui,
    )
