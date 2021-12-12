from binaryninja import BinaryView, HighLevelILOperation, BinaryReader
from enum import Enum


class ConfigStatus(Enum):
    # Configuration is not set
    NOT_SET = 0
    # Configuration is set
    SET = 1
    # There was an error while trying to recover the configuration
    ERROR = 2


def print_kconfig(config: dict):
    """Print kernel configuration to stdout.

    Args:
      config: Recovered kernel configuration results.
    """

    for subsystem, settings in config.items():
        print('#\n' f"# {subsystem}\n" '#')
        for name, setting in settings.items():
            if not setting:
                print(f'# {name} needs looked at manually!')
            elif isinstance(setting, str):
                print(f'{name}="{setting}"')
            elif isinstance(setting, ConfigStatus):
                if setting == ConfigStatus.SET:
                    print(f'{name}=y')
                elif setting == ConfigStatus.NOT_SET:
                    print(f'# {name} is not set')


def to_ulong(i: int) -> int:
    """Convert signed integer to unsigned integer.

    Args:
      i: Signed integer.

    Returns:
      Unsigned integer.
    """

    return i & 0xffffffffffffffff


class KConfigRecover:
    """Class that uses BN API to attempt to recover kernel configurations.
    """
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.br = BinaryReader(self.bv)
        self.helpers = {
            'General Setup': {
                # General setup
                'CONFIG_BUILD_SALT': self._recover_config_build_salt,
                'CONFIG_SWAP': self._recover_config_swap,
                'CONFIG_SYSVIPC': self._recover_config_sysvipc,
                'CONFIG_SYSVIPC_SYSCTL': self._recover_config_sysvipc_sysctl,
                'CONFIG_POSIX_MQUEUE': self._recover_config_posix_mqueue,
                'CONFIG_POSIX_MQUEUE_SYSCTL':
                self._recover_config_posix_mqueue_sysctl,
                'CONFIG_CROSS_MEMORY_ATTACH':
                self._recover_config_cross_memory_attach,
                'CONFIG_USELIB': self._recover_config_uselib,
                'CONFIG_AUDIT': self._recover_config_audit,
                'CONFIG_AUDITSYSCALL': self._recover_config_auditsyscall,
                'CONFIG_AUDIT_WATCH': self._recover_config_audit_watch,
                'CONFIG_AUDIT_TREE': self._recover_config_audit_tree,
            }
        }

    def _recover_config_build_salt(self) -> str:
        """Recover CONFIG_BUILD_SALT configuration.

        Analyze the first call to seq_printf in sched_debug_header and extract the pointer to the build salt from the
        third parameter.

        Returns:
          Build salt string or None.
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

    def _set_if_symbol_present(self, name: str) -> ConfigStatus:
        """Helper for recovering configuration settings that can be determined based on the presence of a symbol

        Args:
          name: Symbol name.

        Returns:
          Determined configuration setting
        """

        if self.bv.get_symbols_by_name(name):
            return ConfigStatus.SET

        return ConfigStatus.NOT_SET

    def _recover_config_swap(self) -> ConfigStatus:
        """Recover CONFIG_SWAP configuration.

        If this configuration is defined then iomap_swapfile_add_extent will be present.
        """

        return self._set_if_symbol_present('iomap_swapfile_add_extent')

    def _recover_config_sysvipc(self) -> ConfigStatus:
        """Recover CONFIG_SYSVIPC configuration.

        Set if sem_init_ns is present.
        """

        return self._set_if_symbol_present('sem_init_ns')

    def _recover_config_sysvipc_sysctl(self):
        """Recover CONFIG_SYSVIPC_SYSCTL configuration.

        Set if ipc_kern_table is present.
        """

        return self._set_if_symbol_present('ipc_kern_table')

    def _recover_config_posix_mqueue(self):
        """Recover CONFIG_POSIX_MQUEUE configuration.

        Set if mq_init_ns is present.
        """

        return self._set_if_symbol_present('mq_init_ns')

    def _recover_config_posix_mqueue_sysctl(self):
        """Recover CONFIG_POSIX_MQUEUE_SYSCTL configuration.

        Set if mq_register_sysctl_table is present.
        """

        return self._set_if_symbol_present('mq_register_sysctl_table')

    def _recover_config_cross_memory_attach(self):
        """Recover CONFIG_CROSS_MEMORY_ATTACH configuration.

        Set if any of the symbols in process_vm_access.c are present
        """

        if self.bv.platform.arch.name == 'x86_64':
            return self._set_if_symbol_present('__x64_sys_process_vm_readv')

        # Unimplemented architecture
        return ConfigStatus.ERROR

    def _recover_config_uselib(self):
        """Recover CONFIG_USELIB configuration.

        Set if sys_uselib is present.
        """

        if self.bv.platform.arch.name == 'x86_64':
            return self._set_if_symbol_present('__x64_sys_uselib')

    def _recover_config_audit(self):
        """Recover CONFIG_AUDIT configuration.

        Set if symbols from kernel/audit.c are present.
        """

        return self._set_if_symbol_present('audit_log_start')

    def _recover_config_auditsyscall(self):
        """Recover CONFIG_AUDITSYSCALL configuration.

        Set if symbols from kernel/auditsc.c are present.
        """

        return self._set_if_symbol_present('audit_filter_inodes')

    def _recover_config_audit_watch(self):
        """Recover CONFIG_AUDIT_WATCH configuration.

        Set if symbols from kernel/audit_watch.c are present.
        """

        return self._set_if_symbol_present('audit_exe_compare')

    def _recover_config_audit_tree(self):
        """Recover CONFIG_AUDIT_TREE configuration.

        Set if symbols from kernel/audit_tree.c are present.
        """

        return self._set_if_symbol_present('audit_kill_trees')

    def do(self) -> dict:
        """Analyze binary and recover kernel configurations

        Returns:
          Dictionary of recovered configurations
        """

        results = dict()
        for subsystem, settings in self.helpers.items():
            results[subsystem] = dict()
            for setting, helper in settings.items():
                results[subsystem][setting] = helper()

        return results
