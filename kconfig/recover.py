from binaryninja import BinaryView, HighLevelILOperation, BinaryReader
from enum import Enum
import logging


class ConfigStatus(Enum):
    # Configuration is not set
    NOT_SET = 0
    # Configuration is set
    SET = 1
    # There was an error while trying to recover the configuration
    ERROR = 2


def save_kconfig(config: dict, filepath: str):
    """Save kernel configuration to a file.

    Args:
      config: Recovered kernel configuration results.
      filepath: Path to output kconfig file.
    """

    with open(filepath, 'w') as f:
        for subsystem, settings in config.items():
            f.write('#\n' f"# {subsystem}\n" '#\n')
            for name, setting in settings.items():
                if not setting:
                    f.write(f'# {name} needs user intervention\n')
                elif isinstance(setting, str):
                    f.write(f'{name}="{setting}"\n')
                elif isinstance(setting, ConfigStatus):
                    if setting == ConfigStatus.SET:
                        f.write(f'{name}=y\n')
                    elif setting == ConfigStatus.NOT_SET:
                        f.write(f'# {name} is not set\n')
                    elif setting == ConfigStatus.ERROR:
                        f.write(f'# {name} needs user intervention\n')
            f.write('\n')

    logging.info(f'Recovered kconfig saved to "{filepath}"')


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
                'CONFIG_CLOCKSOURCE_WATCHDOG':
                self._recover_config_clocksource_watchdog,
                'CONFIG_ARCH_CLOCKSOURCE_DATA':
                self._recover_config_arch_clocksource_data,
                # TODO: I think we can get this one, but it will be a lot of work and won't make a difference for
                # building drivers. See kernel/time/timekeeping_internal.h
                'CONFIG_CLOCKSOURCE_VALIDATE_LAST_CYCLE':
                None,
                'CONFIG_GENERIC_TIME_VSYSCALL':
                self._recover_config_generic_time_vsyscall,
                'CONFIG_GENERIC_CLOCKEVENTS':
                self._recover_config_generic_clockevents,
                'CONFIG_GENERIC_CLOCKEVENTS_BROADCAST':
                self._recover_config_generic_clockevents_broadcast,
                # TODO: Another one we might be able to get, but may not be worth the effort. Slightly changes
                # clockevents_program_min_delta, a static function in kernel/time/clockevents.c
                'CONFIG_GENERIC_CLOCKEVENTS_MIN_BROADCAST':
                None,
                'CONFIG_GENERIC_CMOS_UPDATE':
                self._recover_config_generic_cmos_update,
            },
            'Timer Subsystem': {
                'CONFIG_TICK_ONESHOT': self._recover_config_tick_oneshot,
                'CONFIG_NO_HZ_COMMON': self._recover_config_no_hz_common,
                'CONFIG_NO_HZ_FULL': self._recover_config_no_hz_full,
                # CONFIG_NO_HZ_IDLE, CONFIG_NO_HZ_PERIODIC, and CONFIG_NO_HZ don't seem to be used in v4.18 kernel
                'CONFIG_NO_HZ_IDLE': None,
                'CONFIG_HZ_PERIODIC': None,
                'CONFIG_NO_HZ': None,
                'CONFIG_HIGH_RES_TIMERS': self._recover_config_high_res_timers,
                'CONFIG_PREEMPT_VOLUNTARY':
                self._recover_config_preempt_voluntary,
                'CONFIG_PREEMPT': self._recover_config_preempt,
            },
            'CPU/Task time and stats accounting': {
                'CONFIG_TICK_CPU_ACCOUNTING':
                self._recover_config_tick_cpu_accounting,
                'CONFIG_VIRT_CPU_ACCOUNTING_GEN':
                self._recover_config_virt_cpu_accounting_gen,
                'CONFIG_IRQ_TIME_ACCOUNTING':
                self._recover_config_irq_time_accounting,
                'CONFIG_BSD_PROCESS_ACCT':
                self._recover_config_bsd_process_acct,
                # See include/linux/acct.h
                'CONFIG_BSD_PROCESS_ACCT_V3': None,
                'CONFIG_TASKSTATS': self._recover_config_taskstats,
                'CONFIG_TASK_DELAY_ACCT': self._recover_config_task_delay_acct,
                'CONFIG_TASK_XACCT': self._recover_config_task_xacct,
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
            logging.error('Failed to lookup sched_debug_header')
            return None

        sched_debug_header = self.bv.get_function_at(syms[0].address)
        if not sched_debug_header:
            logging.error('Failed to get function sched_debug_header')
            return None

        syms = self.bv.get_symbols_by_name('seq_printf')
        if not syms:
            logging.error('Failed to lookup seq_printf')
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
                        logging.error(
                            'First call in sched_debug header is not to seq_printf!?'
                        )
                        return None

                    if instr.params[
                            2].operation != HighLevelILOperation.HLIL_CONST_PTR:
                        logging.error(
                            'param3 of seq_printf call is not a pointer')
                        return None

                    s = self.bv.get_ascii_string_at(
                        to_ulong(instr.params[2].constant))
                    if not s:
                        logging.error('Failed to get build salt string')
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

    def _recover_config_sysvipc_sysctl(self) -> ConfigStatus:
        """Set if ipc_kern_table is present.
        """

        return self._set_if_symbol_present('ipc_kern_table')

    def _recover_config_posix_mqueue(self) -> ConfigStatus:
        """Set if mq_init_ns is present.
        """

        return self._set_if_symbol_present('mq_init_ns')

    def _recover_config_posix_mqueue_sysctl(self) -> ConfigStatus:
        """Set if mq_register_sysctl_table is present.
        """

        return self._set_if_symbol_present('mq_register_sysctl_table')

    def _recover_config_cross_memory_attach(self) -> ConfigStatus:
        """Set if any of the symbols in process_vm_access.c are present
        """

        if self.bv.platform.arch.name == 'x86_64':
            return self._set_if_symbol_present('__x64_sys_process_vm_readv')

        logging.error(
            f'Architecture is unsupported {self.bv.platform.arch.name}')
        return ConfigStatus.ERROR

    def _recover_config_uselib(self) -> ConfigStatus:
        """Set if sys_uselib is present.
        """

        if self.bv.platform.arch.name == 'x86_64':
            return self._set_if_symbol_present('__x64_sys_uselib')

        logging.error(
            f'Architecture is unsupported {self.bv.platform.arch.name}')
        return ConfigStatus.ERROR

    def _recover_config_audit(self) -> ConfigStatus:
        """Set if symbols from kernel/audit.c are present.
        """

        return self._set_if_symbol_present('audit_log_start')

    def _recover_config_auditsyscall(self) -> ConfigStatus:
        """Set if symbols from kernel/auditsc.c are present.
        """

        return self._set_if_symbol_present('audit_filter_inodes')

    def _recover_config_audit_watch(self) -> ConfigStatus:
        """Set if symbols from kernel/audit_watch.c are present.
        """

        return self._set_if_symbol_present('audit_exe_compare')

    def _recover_config_audit_tree(self) -> ConfigStatus:
        """Set if symbols from kernel/audit_tree.c are present.
        """

        return self._set_if_symbol_present('audit_kill_trees')

    def _recover_config_generic_irq_probe(self) -> ConfigStatus:
        """Set if symbols from kernel/irq/autoprobe.c are present.
        """

        return self._set_if_symbol_present('probe_irq_on')

    def _recover_config_generic_irq_show(self) -> ConfigStatus:
        """Set if arch_show_interrupts symbol is present.
        """

        return self._set_if_symbol_present('arch_show_interrupts')

    def _recover_config_generic_irq_effective_aff_mask(self) -> ConfigStatus:
        """Set if effective_affinity_list string is present in the binary. See proc.c:register_irq_proc.
        """

        return self._set_if_string_present('effective_affinity_list')

    def _recover_config_generic_pending_irq(self) -> ConfigStatus:
        """Set if any symbols from kernel/irq/migration.c are present.
        """

        return self._set_if_symbol_present('irq_fixup_move_pending')

    def _recover_config_generic_irq_migration(self) -> ConfigStatus:
        """Set if any symbols from kernel/irq/cpuhotplug.c are present.
        """

        return self._set_if_symbol_present('irq_migrate_all_off_this_cpu')

    def _recover_config_generic_irq_chip(self) -> ConfigStatus:
        """Set if any symbols from kernel/irq/generic-chip.c are present.
        """

        return self._set_if_symbol_present('irq_gc_mask_disable_reg')

    def _recover_config_irq_domain(self) -> ConfigStatus:
        """Set if any symbols from kernel/irq/irqdomain.c are present.
        """

        return self._set_if_symbol_present('irq_domain_free_fwnode')

    def _recover_config_irq_domain_hierarchy(self) -> ConfigStatus:
        """Set if irq_domain_create_hierarchy from kernel/irq/irqdomain.c is present.
        """

        return self._set_if_symbol_present('irq_domain_create_hierarchy')

    def _recover_config_generic_msi_irq(self) -> ConfigStatus:
        """Set if symbols from kernel/irq/msi.c are present.
        """

        return self._set_if_symbol_present('alloc_msi_entry')

    def _recover_config_generic_msi_irq_domain(self) -> ConfigStatus:
        """Set if msi_domain_set_affinity from kernel/irq/msi.c is present.
        """

        return self._set_if_symbol_present('msi_domain_set_affinity')

    def _recover_config_generic_irq_matrix_allocator(self) -> ConfigStatus:
        """Set if any symbols from kernel/irq/matrix.c are present.
        """

        return self._set_if_symbol_present('irq_matrix_online')

    def _recover_config_irq_forced_threading(self) -> ConfigStatus:
        """Set if force_irqthreads from kernel/irq/manage.c is present.
        """

        return self._set_if_symbol_present('force_irqthreads')

    def _recover_config_sparse_irq(self) -> ConfigStatus:
        """Set if irq_lock_sparse from  kernel/irq/irqdesc.c is present.
        """

        return self._set_if_symbol_present('irq_lock_sparse')

    def _recover_config_generic_irq_debugfs(self) -> ConfigStatus:
        """Set if any symbols from kernel/irq/debugfs.c are present.
        """

        return self._set_if_symbol_present('irq_debugfs_copy_devname')

    def _recover_config_clocksource_watchdog(self) -> ConfigStatus:
        """Set if clocksource_watchdog_work from kernel/time/clocksource.c is present.
        """

        return self._set_if_symbol_present('clocksource_watchdog_work')

    def _recover_config_arch_clocksource_data(self) -> ConfigStatus:
        """Set unconditionally for certain architectures.
        """

        if self.bv.platform.arch.name == 'x86_64':
            return ConfigStatus.SET

        logging.error(
            f'Architecture is unsupported {self.bv.platform.arch.name}')
        return ConfigStatus.ERROR

    def _recover_config_generic_time_vsyscall(self) -> ConfigStatus:
        """Set if update_vsyscall from include/linux/timekeeper_internal.h is present.
        """

        return self._set_if_symbol_present('update_vsyscall')

    def _recover_config_generic_clockevents(self) -> ConfigStatus:
        """Set if any symbols from kernel/time/clockevents.c are present.
        """

        return self._set_if_symbol_present('clockevent_delta2ns')

    def _recover_config_generic_clockevents_broadcast(self) -> ConfigStatus:
        """Set if any symbols from kernel/time/tick-broadcast.c are present.
        """

        return self._set_if_symbol_present('tick_receive_broadcast')

    def _recover_config_generic_cmos_update(self) -> ConfigStatus:
        """Set if update_persistent_clock from kernel/time/ntp.c is present
        """

        return self._set_if_symbol_present('update_persistent_clock64')

    def _recover_config_tick_oneshot(self) -> ConfigStatus:
        """Set if any symbols from tick-oneshot.c are present
        """

        return self._set_if_symbol_present('tick_program_event')

    def _recover_config_no_hz_common(self) -> ConfigStatus:
        """Set if calc_load_nohz_start from include/linux/sched/nohz.h is present.
        """

        return self._set_if_symbol_present('calc_load_nohz_start')

    def _recover_config_no_hz_full(self) -> ConfigStatus:
        """Set if rcu_user_enter from kernel/rcu/tree.c is present.
        """

        return self._set_if_symbol_present('rcu_user_enter')

    def _recover_config_high_res_timers(self) -> ConfigStatus:
        """Set if clock_was_set_delayed from include/linux/hrtimer.h is present.
        """

        return self._set_if_symbol_present('clock_was_set_delayed')

    def _recover_config_preempt(self) -> ConfigStatus:
        """Set if preempt_schedule from kernel/sched/core.c is present.
        """

        return self._set_if_symbol_present('preempt_schedule')

    def _recover_config_preempt_voluntary(self) -> ConfigStatus:
        """Set if mmiotrace_iounmap calls _cond_resched.

        This starts with include/linux/kernel.h. If the configuration is set, then might_resched calls _cond_resched.
        The might_sleep macro calls might_resched, and mmiotrace_iounmap calls might_sleep.
        """

        syms = self.bv.get_symbols_by_name('_cond_resched')
        if not syms:
            logging.error('Failed to lookup _cond_resched')
            return ConfigStatus.ERROR

        xrefs = self.bv.get_code_refs(syms[0].address)
        for xref in xrefs:
            if xref.function.name == 'mmiotrace_iounmap':
                return ConfigStatus.SET

        return ConfigStatus.NO_SET

    def _recover_config_tick_cpu_accounting(self) -> ConfigStatus:
        """Set if architecture is not PPC64.
        """

        if self.bv.platform.arch.name == 'x86_64':
            return ConfigStatus.SET

        logging.error(
            f'Architecture is unsupported {self.bv.platform.arch.name}')
        return ConfigStatus.ERROR

    def _recover_config_virt_cpu_accounting_gen(self) -> ConfigStatus:
        """Set if vtime_user_enter from include/linux/vtime.h is present.
        """

        return self._set_if_symbol_present('vtime_user_enter')

    def _recover_config_irq_time_accounting(self) -> ConfigStatus:
        """Set if irqtime_account_irq from include/linux/vtime.h is present.
        """

        return self._set_if_symbol_present('irqtime_account_irq')

    def _recover_config_bsd_process_acct(self) -> ConfigStatus:
        """Set if any symbols from kernel/acct.c are present.
        """

        return self._set_if_symbol_present('acct_exit_ns')

    def _recover_config_taskstats(self) -> ConfigStatus:
        """Set if any symbols from kernel/taskstats.c are present.
        """

        return self._set_if_symbol_present('taskstats_exit')

    def _recover_config_task_delay_acct(self) -> ConfigStatus:
        """Set if any symbols from kernel/delayacct.c.
        """

        return self._set_if_symbol_present('delayacct_init')

    def _recover_config_task_xacct(self) -> ConfigStatus:
        """Set if xacct_add_tsk from kernel/tsacct.c.
        """

        return self._set_if_symbol_present('xacct_add_tsk')

    def do(self) -> dict:
        """Analyze binary and recover kernel configurations

        Returns:
          Dictionary of recovered configurations
        """

        results = dict()
        for subsystem, settings in self.helpers.items():
            logging.info(f'Recovering "{subsystem}" configurations...')
            results[subsystem] = dict()
            for setting, helper in settings.items():
                if helper:
                    results[subsystem][setting] = helper()
                else:
                    results[subsystem][setting] = None

        # Some post-processing configs
        if results['Timer Subsystem'][
                'CONFIG_PREEMPT_VOLUNTARY'] is ConfigStatus.SET or results[
                    'Timer Subsystem']['CONFIG_PREEMPT'] is ConfigStatus.SET:
            results['Timer Subsystem'][
                'CONFIG_PREEMPT_NONE'] = ConfigStatus.NOT_SET
        else:
            results['Timer Subsystem'][
                'CONFIG_PREEMPT_NONE'] = ConfigStatus.SET

        return results
