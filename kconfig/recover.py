from binaryninja import BinaryView, HighLevelILOperation


class KConfigRecover:
    """Class that uses BN API to attempt to recover kernel configurations.
    """
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.helpers = {
            'CONFIG_BUILD_SALT': self._recover_config_build_salt,
        }

    def _recover_config_build_salt(self) -> str:
        """Recover CONFIG_BUILD_SALT configuration

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

                print(f'{hex(instr.dest.constant)} {hex(syms[0].address)}')
                if instr.dest.constant & 0xffffffffffffffff == syms[0].address:
                    if len(instr.params) < 3:
                        return None

                    if instr.params[
                            2].operation != HighLevelILOperation.HLIL_CONST_PTR:
                        return None

                    salt = self.bv.get_string_at(instr.params[2].constant
                                                 & 0xffffffffffffffff)
                    print(
                        f'salt: {salt} {hex(instr.params[2].constant & 0xffffffffffffffff)}'
                    )
                    return salt

    def do(self) -> dict:
        """Analyze binary and recover kernel configurations

        Returns:
          Dictionary of recovered configurations
        """

        results = dict()
        for setting, helper in self.helpers.items():
            results[setting] = helper()

        return results
