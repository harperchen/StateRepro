"""
Obtain call trace from raw kernel crash dump
"""

import re

class DumpResolver:
    def __init__(self):
        # kasan, kmasn, info hang
        self.kasan_patterns = [
            "Call Trace:\n([\s\S]*?)\n(RIP: 00|Allocated by task|===)",  # group 0
        ]

        # group 0 and 1
        self.kernel_bug_pattern = "RIP: 0010:([\s\S]*?)Code[\s\S]*R13:[\s\S]*Call Trace:\n([\s\S]*?)\nModules linked in"

        # warn
        self.warn_patterns = [
            "RIP: 0010:([\s\S]*?)RSP[\s\S]*?Call Trace:\n([\s\S]*?)(Allocated by task|Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)",
            "RIP: 0010:([\s\S]*?)Code[\s\S]*?Call Trace:\n([\s\S]*?)(Allocated by task|Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)",
            "RIP: 0010:([\s\S]*?)Code[\s\S]*?R13:.*?\n([\s\S]*?)(Allocated by task|Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)",
            "RIP: 0010:([\s\S]*?)RSP[\s\S]*?R13:.*?\n([\s\S]*?)(Allocated by task|Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)",
            "RIP: 0010:([\s\S]*)Code[\s\S]*?Call Trace:\n([\s\S]*?)(Allocated by task|Kernel Offset|entry_SYSCALL)"
        ]

        self.remain_patterns = [
            "Call Trace:\n([\s\S]*?)\n(Allocated by task|Modules linked in| ret_from_fork|Code|irq event stamp:|---\[ end trace|RIP: 00)"
        ]

    @staticmethod
    def get_call_trace(pattern, report):
        p = re.compile(pattern)
        m = p.search(report)
        if not m:
            return None
        trace = m.group(1)
        if "invalid_op" in trace:
            return None
        if "Code: " in trace:
            return None
        return m


    @staticmethod
    def produce_call_trace(report: str) -> str:
        report = report.strip()
        report_lines = []
        for line in report.split('\n'):
            new_line = line.strip()
            prefixes = ('RSP:', 'RAX:', 'RDX:', 'RBP:', 'R10:', 'R13:', 'RIP: 0033:')
            if new_line.startswith(prefixes):
                continue
            new_line = line.replace('RIP: 0010:', '')
            new_line = new_line.replace('<TASK>', '')
            new_line = new_line.strip()
            if new_line == '':
                continue
            report_lines.append(new_line)
        return '\n'.join(report_lines)

    def parse_call_trace(self, report: str) -> str:
        report = report.strip()
        # TODO: call trace is not parsed so far
        if 'Call trace:\n' in report:
            report = report.replace('Call trace:\n', 'Call Trace:\n')

        if 'Call Trace:\n' not in report:
            return ""

        report += "\nAllocated by task"
        raw_call_trace = None
        if "WARNING" in report or "GPF" in report or "kernel BUG at" in report \
                or "BUG: unable to handle" in report:
            for pattern in self.warn_patterns:
                found = self.get_call_trace(pattern, report)
                if found:
                    raw_call_trace = found.group(1) + found.group(2)
                    break  # Exit the loop once a result is fo
            if raw_call_trace is not None:
                return self.produce_call_trace(raw_call_trace)
        elif "kasan" in report or 'kmsan' in report or 'ubsan' in report:
            for pattern in self.kasan_patterns:
                found = self.get_call_trace(pattern, report)
                if found:
                    raw_call_trace = found.group(1)
                    break  # Exit the loop once a result is fo
            if raw_call_trace is not None:
                return self.produce_call_trace(raw_call_trace)
        else:
            pass

        for pattern in self.remain_patterns:
            found = self.get_call_trace(pattern, report)
            if found:
                raw_call_trace = found.group(1)
                break  # Exit the loop once a result is fo
        if raw_call_trace is not None:
            return self.produce_call_trace(raw_call_trace)
        else:
            if 'invalid_op' not in report:
                print('!!!Warning: cannot find call trace')
                print(report)
                return ''
            else:
                return 'invalid report'

    def if_call_trace_from_syscall(self, call_trace):
        """
        verify if current call trace is related to syscall execution
        """
        if 'do_syscall_x64' in call_trace:
            return True
        if ('do_syscall_64' in call_trace or
            'entry_SYSCALL_64' in call_trace) \
                and ('__x64_sys_' in call_trace
                     or '__sys_' in call_trace
                     or 'SyS_' in call_trace
                     or 'ksys_' in call_trace
                     or '__do_sys' in call_trace
                     or '__se_sys' in call_trace
                     or 'do_sys_' in call_trace
        ):
            # crash is triggered when executing syscall on x86_64
            return True
        elif '__do_fast_syscall_32' in call_trace or 'do_fast_syscall_32' in call_trace:
            return True
        elif '__arm64_sys_' in call_trace or '__invoke_syscall' in call_trace:
            return True
        elif 'do_readv' in call_trace or 'io_uring_setup' in call_trace or 'do_mkdirat' in call_trace \
                or 'do_writev' in call_trace:
            return True
        else:
            return False

    def if_call_trace_from_forked(self, call_trace):
        """
        verify if current call trace is related to background thread
        """
        if 'ret_from_fork' in call_trace or 'process_one_work' in call_trace:
            return True
        elif 'kthread' in call_trace:
            return True
        else:
            return False

    def if_call_trace_from_interrupt(self, call_trace):
        if '__do_softirq' in call_trace or 'do_IRQ' in call_trace:
            return True
        elif 'apic_timer_interrupt' in call_trace:
            return True
        elif 'sysvec_irq_work' in call_trace:
            return True
        elif '<IRQ>' in call_trace:
            return True
        return False

    def if_call_trace_exit_mode(self, call_trace):
        if 'syscall_return_slowpath' in call_trace:
            return True
        elif '__syscall_exit_to_user_mode_work' in call_trace:
            return True
        elif 'syscall_exit_to_user_mode' in call_trace:
            return True
        elif 'exit_to_user_mode_loop' in call_trace:
            return True
        elif 'exit_to_usermode_loop' in call_trace:
            return True
        elif 'exit_to_user_mode' in call_trace:
            return True
        return False


if __name__ == '__main__':
    resolver = DumpResolver()
    report = \
        """==================================================================
BUG: KASAN: slab-out-of-bounds in class_equal+0x40/0x50 kernel/locking/lockdep.c:1527
Read of size 8 at addr ffff888086037440 by task syz-executor.1/10102

CPU: 1 PID: 10102 Comm: syz-executor.1 Not tainted 5.2.0-rc6+ #34
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
Call Trace:

Allocated by task 9813:
 save_stack+0x23/0x90 mm/kasan/common.c:71
 set_track mm/kasan/common.c:79 [inline]
 __kasan_kmalloc mm/kasan/common.c:489 [inline]
 __kasan_kmalloc.constprop.0+0xcf/0xe0 mm/kasan/common.c:462
 kasan_kmalloc+0x9/0x10 mm/kasan/common.c:503
 __do_kmalloc mm/slab.c:3660 [inline]
 __kmalloc+0x15c/0x740 mm/slab.c:3669
 kmalloc_array include/linux/slab.h:670 [inline]
 batadv_hash_new+0xaf/0x2f0 net/batman-adv/hash.c:56
 batadv_tt_global_init net/batman-adv/translation-table.c:1492 [inline]
 batadv_tt_init+0x26a/0x330 net/batman-adv/translation-table.c:4403
 batadv_mesh_init+0x4f5/0x700 net/batman-adv/main.c:208
 batadv_softif_init_late+0xc27/0xea0 net/batman-adv/soft-interface.c:861
 register_netdevice+0x2fd/0xff0 net/core/dev.c:8663
 __rtnl_newlink+0x146b/0x16c0 net/core/rtnetlink.c:3199
 rtnl_newlink+0x69/0xa0 net/core/rtnetlink.c:3245
 rtnetlink_rcv_msg+0x463/0xb00 net/core/rtnetlink.c:5214
 netlink_rcv_skb+0x177/0x450 net/netlink/af_netlink.c:2482
 rtnetlink_rcv+0x1d/0x30 net/core/rtnetlink.c:5232
 netlink_unicast_kernel net/netlink/af_netlink.c:1307 [inline]
 netlink_unicast+0x531/0x710 net/netlink/af_netlink.c:1333
 netlink_sendmsg+0x8ae/0xd70 net/netlink/af_netlink.c:1922
 sock_sendmsg_nosec net/socket.c:646 [inline]
 sock_sendmsg+0xd7/0x130 net/socket.c:665
 __sys_sendto+0x262/0x380 net/socket.c:1958
 __do_sys_sendto net/socket.c:1970 [inline]
 __se_sys_sendto net/socket.c:1966 [inline]
 __x64_sys_sendto+0xe1/0x1a0 net/socket.c:1966
 do_syscall_64+0xfd/0x680 arch/x86/entry/common.c:301
 entry_SYSCALL_64_after_hwframe+0x49/0xbe
    """
    print(resolver.parse_call_trace(report))
