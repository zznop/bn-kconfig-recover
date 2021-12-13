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
                elif setting == ConfigStatus.ERROR:
                    print(f'# {name} needs looked at manually!')
        print()


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
            },
            'IRQ Subsystem': {
                'CONFIG_GENERIC_IRQ_PROBE':
                self._recover_config_generic_irq_probe,
                'CONFIG_GENERIC_IRQ_SHOW':
                self._recover_config_generic_irq_show,
                'CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK':
                self._recover_config_generic_irq_effective_aff_mask,
                'CONFIG_GENERIC_PENDING_IRQ':
                self._recover_config_generic_pending_irq,
                'CONFIG_GENERIC_IRQ_MIGRATION':
                self._recover_config_generic_irq_migration,
                'CONFIG_GENERIC_IRQ_CHIP':
                self._recover_config_generic_irq_chip,
                'CONFIG_IRQ_DOMAIN':
                self._recover_config_irq_domain,
                'CONFIG_IRQ_DOMAIN_HIERARCHY':
                self._recover_config_irq_domain_hierarchy,
                'CONFIG_GENERIC_MSI_IRQ':
                self._recover_config_generic_msi_irq,
                'CONFIG_GENERIC_MSI_IRQ_DOMAIN':
                self._recover_config_generic_msi_irq_domain,
                'CONFIG_GENERIC_IRQ_MATRIX_ALLOCATOR':
                self._recover_config_generic_irq_matrix_allocator,
                # There is no way to determine whether or not this setting is set. It's used for PCI drivers (see drivers/pci/msi.c)
                'CONFIG_GENERIC_IRQ_RESERVATION_MODE':
                None,
                'CONFIG_IRQ_FORCED_THREADING':
                self._recover_config_irq_forced_threading,
                'CONFIG_SPARSE_IRQ':
                self._recover_config_sparse_irq,
                'CONFIG_GENERIC_IRQ_DEBUGFS':
                self._recover_config_generic_irq_debugfs,
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
          Configuration setting.
        """

        if self.bv.get_symbols_by_name(name):
            return ConfigStatus.SET

        return ConfigStatus.NOT_SET

    def _set_if_string_present(self, value: str) -> ConfigStatus:
        """Helper for recovering configuration settings that can be determined based on the presence of a string

        Args:
          value: String value.

        Returns:
          Configuration setting.
        """
        strings = self.bv.get_strings()
        for s in strings:
            if s.value == value:
                return ConfigStatus.SET

        return ConfigStatus.NOT_SET

    def _recover_config_swap(self) -> ConfigStatus:
        """If this configuration is defined then iomap_swapfile_add_extent will be present.
        """

        return self._set_if_symbol_present('iomap_swapfile_add_extent')

    def _recover_config_sysvipc(self) -> ConfigStatus:
        """Set if sem_init_ns is present.
        """

        return self._set_if_symbol_present('sem_init_ns')

    def _recover_config_sysvipc_sysctl(self):
        """Set if ipc_kern_table is present.
        """

        return self._set_if_symbol_present('ipc_kern_table')

    def _recover_config_posix_mqueue(self):
        """Set if mq_init_ns is present.
        """

        return self._set_if_symbol_present('mq_init_ns')

    def _recover_config_posix_mqueue_sysctl(self):
        """Set if mq_register_sysctl_table is present.
        """

        return self._set_if_symbol_present('mq_register_sysctl_table')

    def _recover_config_cross_memory_attach(self):
        """Set if any of the symbols in process_vm_access.c are present
        """

        if self.bv.platform.arch.name == 'x86_64':
            return self._set_if_symbol_present('__x64_sys_process_vm_readv')

        # Unimplemented architecture
        return ConfigStatus.ERROR

    def _recover_config_uselib(self):
        """Set if sys_uselib is present.
        """

        if self.bv.platform.arch.name == 'x86_64':
            return self._set_if_symbol_present('__x64_sys_uselib')

    def _recover_config_audit(self):
        """Set if symbols from kernel/audit.c are present.
        """

        return self._set_if_symbol_present('audit_log_start')

    def _recover_config_auditsyscall(self):
        """Set if symbols from kernel/auditsc.c are present.
        """

        return self._set_if_symbol_present('audit_filter_inodes')

    def _recover_config_audit_watch(self):
        """Set if symbols from kernel/audit_watch.c are present.
        """

        return self._set_if_symbol_present('audit_exe_compare')

    def _recover_config_audit_tree(self):
        """Set if symbols from kernel/audit_tree.c are present.
        """

        return self._set_if_symbol_present('audit_kill_trees')

    def _recover_config_generic_irq_probe(self):
        """Set if symbols from kernel/irq/autoprobe.c are present.
        """

        return self._set_if_symbol_present('probe_irq_on')

    def _recover_config_generic_irq_show(self):
        """Set if arch_show_interrupts symbol is present.
        """

        return self._set_if_symbol_present('arch_show_interrupts')

    def _recover_config_generic_irq_effective_aff_mask(self):
        """Set if effective_affinity_list string is present in the binary. See proc.c:register_irq_proc.
        """

        return self._set_if_string_present('effective_affinity_list')

    def _recover_config_generic_pending_irq(self):
        """Set if any symbols from kernel/irq/migration.c are present.
        """

        return self._set_if_symbol_present('irq_fixup_move_pending')

    def _recover_config_generic_irq_migration(self):
        """Set if any symbols from kernel/irq/cpuhotplug.c are present.
        """

        return self._set_if_symbol_present('irq_migrate_all_off_this_cpu')

    def _recover_config_generic_irq_chip(self):
        """Set if any symbols from kernel/irq/generic-chip.c are present.
        """

        return self._set_if_symbol_present('irq_gc_mask_disable_reg')

    def _recover_config_irq_domain(self):
        """Set if any symbols from kernel/irq/irqdomain.c are present.
        """

        return self._set_if_symbol_present('irq_domain_free_fwnode')

    def _recover_config_irq_domain_hierarchy(self):
        """Set if irq_domain_create_hierarchy from kernel/irq/irqdomain.c is present.
        """

        return self._set_if_symbol_present('irq_domain_create_hierarchy')

    def _recover_config_generic_msi_irq(self):
        """Set if symbols from kernel/irq/msi.c are present.
        """

        return self._set_if_symbol_present('alloc_msi_entry')

    def _recover_config_generic_msi_irq_domain(self):
        """Set if msi_domain_set_affinity from kernel/irq/msi.c is present.
        """

        return self._set_if_symbol_present('msi_domain_set_affinity')

    def _recover_config_generic_irq_matrix_allocator(self):
        """Set if any symbols from kernel/irq/matrix.c are present.
        """

        return self._set_if_symbol_present('irq_matrix_online')

    def _recover_config_irq_forced_threading(self):
        """Set if force_irqthreads from kernel/irq/manage.c is present.
        """

        return self._set_if_symbol_present('force_irqthreads')

    def _recover_config_sparse_irq(self):
        """Set if irq_lock_sparse from  kernel/irq/irqdesc.c is present.
        """

        return self._set_if_symbol_present('irq_lock_sparse')

    def _recover_config_generic_irq_debugfs(self):
        """Set if any symbols from kernel/irq/debugfs.c are present.
        """

        return self._set_if_symbol_present('irq_debugfs_copy_devname')

    def do(self) -> dict:
        """Analyze binary and recover kernel configurations

        Returns:
          Dictionary of recovered configurations
        """

        results = dict()
        for subsystem, settings in self.helpers.items():
            results[subsystem] = dict()
            for setting, helper in settings.items():
                if helper:
                    results[subsystem][setting] = helper()
                else:
                    results[subsystem][setting] = None

        return results
