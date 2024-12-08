"""
Locate crashed syscall trace from console log based on several clue:
1. crashed syscall name
2. hints about previous executed syscalls
"""

from typing import List


class PoCResolver:
    def __init__(self):
        pass

    def parse_sysprog(self, syz_prog: str) -> str:
        syscall_names = []
        for line in syz_prog.split('\n'):
            if line.startswith('#'):
                continue
            idx1 = line.find('(')
            idx2 = line.find('=')
            if idx1 != -1:
                if idx2 != -1 and idx2 < idx1:
                    name = line[idx2 + 2: idx1]
                else:
                    name = line[:idx1]
                syscall_names.append(name)
        return '-'.join(syscall_names)

    @staticmethod
    def is_sub_array(array1: List[str], array2: List[str]):
        i = 0  # Pointer for array1
        j = 0  # Pointer for array2

        while i < len(array1) and j < len(array2):
            if array1[i].startswith(array2[j]):
                i += 1
            j += 1

        return i == len(array1)  # Return True if all elements of array1 were found in array2

    def match_poc_and_log(self, log, repro) -> bool:
        """
        TODO: more fine-grained matching, currently we do not consider subsystem, say, only ioctl is consider, while
        ioctl$XX is not considered
        """
        repro_syscalls = repro.split('-')
        for log_item in log.split('\n'):
            log_item_syscalls = log_item.split('-')
            if self.is_sub_array(repro_syscalls, log_item_syscalls):
                print("Find matched execution log and reproducer")
                print("Program in execution log:", log_item)
                print("Reproducer:", repro)
                return True
        return False

                
    @staticmethod
    def calibrate_crashed_call_from_poc(poc: str, inferred_calls: []) -> []:
        correct_crash_syscalls = []
        repro_syzcalls = poc.split('-')
        """
        Four cases here:
           1. exact match, no matter a$1 or a
           2. we can only infer primitive syscall from call trace, say a, but we can find a$1 (a$2, etc) in PoC
           3. we can infer a$1 from call trace, but we find a or a$2 in PoC
           4. we can find a$1 or a from call trace, but no a in PoC, instead we have b in PoC, mainly due to the fact
              that a crash could be triggered via various syscalls
        """
        for call in inferred_calls:
            if call in repro_syzcalls:
                # case 1
                correct_crash_syscalls.append(call)
            elif '$' in call:
                # case 3
                primitive_call = call[:call.find('$')]
                if primitive_call in repro_syzcalls:
                    correct_crash_syscalls.append(primitive_call)
                else:
                    # case 3
                    for correct_call in repro_syzcalls:
                        if '$' in correct_call:
                            correct_primitive = correct_call[:correct_call.find('$')]
                            if correct_primitive != primitive_call:
                                continue
                            correct_crash_syscalls.append(correct_call)
            else:
                # case 2
                for correct_call in repro_syzcalls:
                    if '$' in correct_call:
                        correct_primitive = correct_call[:correct_call.find('$')]
                        if correct_primitive != call:
                            continue
                        correct_crash_syscalls.append(correct_call)

        if len(correct_crash_syscalls) == 0:
            # case 4
            print('!!!Warning: cannot find any match between inferred call and Poc')

        return correct_crash_syscalls

    def guess_if_not_stateful(self):
        # TODO: guess if current crash is related to stateful
        # 1. get all reproducers, such as, a-b-c-d
        # 2. analyze the recorded log
        # 3. check if a reproducer can match call trace
        # 4. check if a reproducer has shown in executed programs

        # all reproducers to trigger the bug
        repros = []
        # execution logs
        logs = []
        # crashed call traces
        call_traces = []

        for item in self.crash_items:
            if item.syscall_names is not None:
                repros.append(item.syscall_names)
            if item.console_log is None:
                item.extract_console_data()
            if item.console_log is not None and item.console_log != "" and \
                    item.call_trace is not None and item.if_call_trace_from_syscall():
                logs.append(item.console_log)
                call_traces.append(item.call_trace)

        # the crash might have multiple call trace to trigger the bug
        for idx, log in enumerate(logs):
            for repro in repros:
                if self.can_we_match(call_traces[idx], repro) and \
                        self.match_log_repro(log, repro):
                    return True
        return False

    @staticmethod
    def can_we_match(call_trace, repro) -> bool:
        """
        If the call trace can be caused by one of the syscall in reproducer
        """
        # the crashed syscall in report might not in reproducer, let's currently omit it
        crashed_syscall = SyscallResolver.parse_call_trace_from_syscall(call_trace)
        for syscall in repro.split('-'):
            if syscall.startswith(crashed_syscall):
                return True
        return False
