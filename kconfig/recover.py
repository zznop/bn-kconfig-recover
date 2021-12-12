from binaryninja import BinaryView, HighLevelILOperation, BinaryReader
from enum import Enum


class ConfigStatus(Enum):
    # Configuration is set
    SET = 1
    # Configuration is not set
    NOT_SET = 2
    # There was an error while trying to recover the configuration
    ERROR = 3


def to_ulong(i: int) -> int:
    """Convert signed integer to unsigned integer

    Args:
      i: signed integer

    Returns:
      Unsigned integer
    """

    return i & 0xffffffffffffffff


class KConfigRecover:
    """Class that uses BN API to attempt to recover kernel configurations.
    """
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.br = BinaryReader(self.bv)
        self.helpers = {
            'CONFIG_BUILD_SALT': self._recover_config_build_salt,
            'CONFIG_SWAP': self._recover_config_swap,
            'CONFIG_SYSVIPC': self._recover_config_sysvipc,
        }

    def _recover_config_build_salt(self) -> str:
        """Recover CONFIG_BUILD_SALT configuration.

        Analyze the first call to seq_printf in sched_debug_header and extract the pointer to the build salt from the
        third parameter.

        Returns:
          Build salt string or None
        """

        syms = self.bv.get_symbols_by_name('sched_debug_header')
        if not syms:
            return None

        sched_debug_header = self.bv.get_function_at(syms[0].address)
        if not sched_debug_header:
            return None

        syms = self.bv.get_symbols_by_name('seq_printf')
        if not syms:
            return None

        call_to_seq_printf = None
        for block in sched_debug_header.high_level_il:
            for instr in block:
                if instr.operation != HighLevelILOperation.HLIL_CALL:
                    continue

                if instr.dest.operation != HighLevelILOperation.HLIL_CONST_PTR:
                    continue

                if to_ulong(instr.dest.constant) == syms[0].address:
                    if len(instr.params) < 3:
                        return None

                    if instr.params[
                            2].operation != HighLevelILOperation.HLIL_CONST_PTR:
                        return None

                    s = self.bv.get_ascii_string_at(
                        to_ulong(instr.params[2].constant))
                    if not s:
                        return None

                    return s.value

    def _recover_config_swap(self) -> ConfigStatus:
        """Recover CONFIG_SWAP configuration.

        If this configuration is defined then iomap_swapfile_add_extent will be present.
        """

        if not self.bv.get_symbols_by_name('iomap_swapfile_add_extent'):
            return ConfigStatus.NOT_SET

        return ConfigStatus.SET

    def _recover_config_sysvipc(self) -> ConfigStatus:
        """Recover CONFIG_SYSVIPC configuration.

        If this configuration is set then sem_init_ns is exported, otherwise it is inlined
        """

        if not self.bv.get_symbols_by_name('sem_init_ns'):
            return ConfigStatus.NOT_SET

        return ConfigStatus.SET

    def do(self) -> dict:
        """Analyze binary and recover kernel configurations

        Returns:
          Dictionary of recovered configurations
        """

        results = dict()
        for setting, helper in self.helpers.items():
            results[setting] = helper()

        return results
