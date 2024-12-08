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
                or "BUG: unable to handle" in report or 'general protection fault' in report:
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
        if '__do_sys_exit_group' in call_trace:
            return True
        if 'SyS_exit_group' in call_trace:
            return True
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
        """general protection fault, probably for non-canonical address 0xdffffc0000000103: 0000 [#1] PREEMPT SMP KASAN
KASAN: null-ptr-deref in range [0x0000000000000818-0x000000000000081f]
CPU: 0 PID: 12816 Comm: syz-executor.1 Not tainted 5.14.0-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
RIP: 0010:io_register_iowq_max_workers fs/io_uring.c:10552 [inline]
RIP: 0010:__io_uring_register fs/io_uring.c:10757 [inline]
RIP: 0010:__do_sys_io_uring_register+0x10e9/0x2e70 fs/io_uring.c:10792
Code: ea 03 80 3c 02 00 0f 85 43 1b 00 00 48 8b 9b a8 00 00 00 b8 ff ff 37 00 48 c1 e0 2a 48 8d bb 18 08 00 00 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 11 1b 00 00 48 8b 9b 18 08 00 00 48 85 db 0f 84
RSP: 0018:ffffc90003f3fdf8 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: 0000000000000000 RCX: 0000000000000000
RDX: 0000000000000103 RSI: 0000000000000004 RDI: 0000000000000818
RBP: ffff888073777900 R08: 0000000000000000 R09: ffff88807e916413
R10: ffffed100fd22c82 R11: 0000000000000001 R12: 0000000000000000
R13: ffffc90003f3fec8 R14: 1ffff920007e7fc9 R15: ffff88805cd7e000
FS:  00007f6c631e3700(0000) GS:ffff8880b9c00000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000001907808 CR3: 0000000062c6d000 CR4: 00000000001506f0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x44/0xae
RIP: 0033:0x4665f9
Code: ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007f6c631e3188 EFLAGS: 00000246 ORIG_RAX: 00000000000001ab
RAX: ffffffffffffffda RBX: 000000000056c038 RCX: 00000000004665f9
RDX: 0000000020004000 RSI: 0000000000000013 RDI: 0000000000000003
RBP: 00000000004bfcc4 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000002 R11: 0000000000000246 R12: 000000000056c038
R13: 00007ffdd807e0af R14: 00007f6c631e3300 R15: 0000000000022000
Modules linked in:
---[ end trace 1cd60a7726ee853d ]---
    """
    print(resolver.parse_call_trace(report))
