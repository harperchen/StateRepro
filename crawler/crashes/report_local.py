import os
from crashes.dump_resolver import *
from crashes.syscall_resolver import *
from crashes.syzkaller_toolbox import *


class KernelReport:
    def __init__(self, report_hash=None, kernel_commit=None, raw_console_log=None, raw_report=None, raw_repro=None,
                 call_trace=None, syscall_names=None, executed_seqs=None, guess_crash_syscalls=[]):
        # raw data
        self.report_hash = report_hash
        self.kernel_commit: str = kernel_commit
        self.raw_report: str = raw_report
        self.raw_console_log: str = raw_console_log
        self.raw_repro: str = raw_repro

        # obtain after analysis
        self.call_trace: str = call_trace
        self.executed_seqs: str = executed_seqs
        self.short_repro: str = syscall_names
        self.guess_crash_syscalls: List[str] = guess_crash_syscalls

        self.dump_resolver = DumpResolver()
        self.syscall_resolver = SyscallResolver()

    def retrieve_report_local(self, report_file: str):
        with open(report_file, 'r') as f:
            self.raw_report = f.read()

    def retrieve_call_trace(self):
        self.call_trace = self.dump_resolver.parse_call_trace(self.raw_report)
        if self.dump_resolver.if_call_trace_from_syscall(self.call_trace):
            self.guess_crash_syscalls.extend(self.syscall_resolver.parse_syscall_from_trace(self.call_trace))
            if len(self.guess_crash_syscalls) == 0:
                print('!!! Warning: cannot resolve crashed syscall')
                print(self.call_trace)

    def retrieve_console_log_local(self, console_log_file: str):
        with open(console_log_file, 'r') as f:
            self.raw_console_log = f.read()

    def retrieve_executed_seqs(self):
        # extract executed programs
        patterns_to_match = ["\d{2}:\d{2}:\d{2} executing program \d+:\n",
                             "\d+(\.\d+)?(s|ms)? ago: executing program \d+ \(id=\d+\):\n"]

        matched_pattern = None
        for pattern in patterns_to_match:
            p = re.compile(pattern)
            m = p.search(self.raw_console_log)
            if m:
                matched_pattern = pattern
                break

        if matched_pattern is None:
            return

        all_executed_progs = []
        for match in re.finditer(matched_pattern, self.raw_console_log):
            segment = match.group()
            end = match.end()

            executed_prog = self.raw_console_log[end:].split('\n\n', 1)[0] + '\n\n'
            segment = segment + executed_prog

            syz_prog = '\n'.join(segment.split('\n')[1:-2])
            all_executed_progs.append(syz_prog)
        self.executed_seqs = '\n\n'.join(all_executed_progs)

    def prepare_repro_testcases(self, repro_dir: str):
        prog_dirs = []
        for prog in self.executed_seqs.split('\n\n'):
            prog_hash = hash_string(prog)[8:]
            prog_dir = os.path.join(repro_dir, prog_hash)
            os.makedirs(prog_dir, exist_ok=True)
            with open(os.path.join(prog_dir, 'testcase'), 'w') as f:
                f.write(prog)
            prog_dirs.append(prog_dir)
        return prog_dirs


class KernelReportDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.custom_object_hook, *args, **kwargs)

    def custom_object_hook(self, obj) -> KernelReport:
        executed_seqs = obj.get('executed_seqs', [])
        guess_crash_syscalls = obj.get('guess_crash_syscalls', [])

        kernelreport = KernelReport(report_hash=obj['report_hash'],
                                    kernel_commit=obj['kernel_commit'],
                                    raw_console_log=obj['raw_console_log'],
                                    raw_report=obj['raw_report'],
                                    raw_repro=obj['raw_repro'],
                                    call_trace=obj['call_trace'],
                                    executed_seqs=executed_seqs,
                                    guess_crash_syscalls=guess_crash_syscalls)
        kernelreport.dump_resolver = DumpResolver()
        kernelreport.syscall_resolver = SyscallResolver()
        return kernelreport
