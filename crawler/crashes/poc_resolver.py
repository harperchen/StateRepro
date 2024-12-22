"""
Locate crashed syscall trace from console log based on several clue:
1. crashed syscall name
2. hints about previous executed syscalls
"""
from crashes.report_local import KernelReport
from crashes.syscall_resolver import SyscallResolver
from utils import *

syscall_resolver = SyscallResolver()


class PoCResolver:
    def __init__(self):
        self.num_crashed_call_correct = 0
        self.num_crashed_primitive_correct = 0

    def locate_crashed_sequence(self, sequence: str, crash_calls: List[str]) -> bool:
        sequence_syscalls = sequence.split('-')
        for syscall in crash_calls:
            if syscall in sequence_syscalls:
                return True
            if '$' in syscall:
                primitive = syscall[:syscall.find('$')]
                if primitive in sequence_syscalls:
                    return True

        return False

    def match_poc_sequence(self, executed_seq: str, poc: str) -> bool:
        pass

    """
    Given two syscall sequence, find maximum matching
    """

    def find_max_seq_matching(self, arr1: List[str], arr2: List[str]):
        n, m = len(arr1), len(arr2)
        dp = [[0] * (m + 1) for _ in range(n + 1)]

        parent = [[None] * (m + 1) for _ in range(n + 1)]

        for i in range(1, n + 1):
            for j in range(1, m + 1):
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

                score = syscall_resolver.compute_match_score(arr1[i - 1], arr2[j - 1])
                if score > 0 and dp[i - 1][j - 1] + score > dp[i][j]:
                    dp[i][j] = dp[i - 1][j - 1] + score
                    parent[i][j] = (i - 1, j - 1)
                else:
                    if dp[i - 1][j] > dp[i][j - 1]:
                        parent[i][j] = (i - 1, j)
                    else:
                        parent[i][j] = (i, j - 1)

        matches = []
        i, j = n, m
        while i > 0 and j > 0:
            pi, pj = parent[i][j]
            if pi == i - 1 and pj == j - 1 and syscall_resolver.compute_match_score(arr1[pi], arr2[pj]) > 0:
                matches.append((pi, pj))
            i, j = pi, pj

        matches.reverse()
        return matches, dp[n][m]

    def calibrate_crashed_call_from_poc(self, poc: str, inferred_calls: []) -> []:
        correct_crash_syscalls = set()
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
                correct_crash_syscalls.add(call)
                self.num_crashed_call_correct += 1
                break

        if len(correct_crash_syscalls) != 0:
            return list(correct_crash_syscalls)

        for call in inferred_calls:
            if '$' in call:
                # case 3
                primitive_call = call[:call.find('$')]
                if primitive_call in repro_syzcalls:
                    self.num_crashed_primitive_correct += 1
                    correct_crash_syscalls.add(primitive_call)
                else:
                    # case 3
                    for correct_call in repro_syzcalls:
                        if '$' in correct_call:
                            correct_primitive = correct_call[:correct_call.find('$')]
                            if correct_primitive != primitive_call:
                                continue
                            self.num_crashed_primitive_correct += 1
                            correct_crash_syscalls.add(correct_call)
            else:
                # case 2
                for correct_call in repro_syzcalls:
                    if '$' in correct_call:
                        correct_primitive = correct_call[:correct_call.find('$')]
                        if correct_primitive != call:
                            continue
                        self.num_crashed_primitive_correct += 1
                        correct_crash_syscalls.add(correct_call)

        if len(correct_crash_syscalls) == 0:
            # case 4
            print('!!!Warning: cannot find any match between inferred call and Poc')
            print('Poc', poc)
            print('Inferred call:', inferred_calls)

        return list(correct_crash_syscalls)

    def extract_suspicious_seq(self, report_items: List[KernelReport]):
        for item_i in report_items:
            if item_i.raw_console_log is None or len(item_i.raw_console_log) == 0:
                continue

            suspicious_seqs = set()
            for idx, executed_seq in enumerate(item_i.executed_seqs.split('\n\n')):
                is_crash_seq = False
                for item_j in report_items:
                    executed_short_seq = parse_sysprog(executed_seq)
                    if hasattr(item_j, 'calibrate_crash_syscalls') and len(item_j.calibrate_crash_syscalls) != 0:
                        is_crash_seq = self.locate_crashed_sequence(executed_short_seq,
                                                                    item_j.calibrate_crash_syscalls)
                    elif len(item_j.guess_crash_syscalls) != 0:
                        is_crash_seq = self.locate_crashed_sequence(executed_short_seq,
                                                                    item_j.guess_crash_syscalls)
                    else:
                        continue

                    if is_crash_seq:
                        break

                if is_crash_seq:
                    suspicious_seqs.add(executed_seq)

            if len(suspicious_seqs) == 0:
                item_i.executed_seqs = ''
            else:
                item_i.executed_seqs = '\n\n'.join(list(suspicious_seqs))
            print(f'Find {len(suspicious_seqs)} in current crash console log')


    def sort_executed_seq_static(self, item: KernelReport, target: str, calibrate_crash_calls: []):
        suspicious_seqs = []
        seq_match_scores = []

        for seq_idx, seq in enumerate(item.executed_seqs.split('\n\n')):
            # de-duplicate
            executed_seq = parse_sysprog(seq).split('-')
            if seq in suspicious_seqs:
                continue

            # check whether more accurate calibrate syscalls in current executed sequence
            if len(calibrate_crash_calls) != 0:
                find_crashed_call = False

                for crash_call in calibrate_crash_calls:
                    if crash_call in executed_seq:
                        find_crashed_call = True
                        break
                if not find_crashed_call:
                    continue

            # compute a match score
            _, match_score = self.find_max_seq_matching(executed_seq, target.split('-'))
            seq_match_scores.append(match_score)
            suspicious_seqs.append(seq)
        paired_list = list(zip(suspicious_seqs, seq_match_scores))
        sorted_paired_list = sorted(paired_list, key=lambda x: x[1],
                                    reverse=True)

        return sorted_paired_list

    def sort_executed_seq_multi_crashed_call(self, all_guessed_crash_syscalls, report_items):
        for item_idx, item in enumerate(report_items):
            if item.raw_console_log is None or len(item.raw_console_log) == 0:
                continue

            for crashed_call in all_guessed_crash_syscalls:
                print('\nGuessed crash syscall: ', crashed_call)

                sorted_paired_list = self.sort_executed_seq_static(item, [crashed_call], [])

                if len(sorted_paired_list) == 0:
                    continue

                max_score_elements = [(element, score) for element, score in sorted_paired_list if score == 1]

                for elem_idx, (element, score) in enumerate(max_score_elements):
                    print('\n- Seq [{}] score of executed seq:'.format(elem_idx), score, 'in',
                          item.console_log_link)
                    print('-', parse_sysprog(element))


    def sort_executed_seq_dynamic(self, report_items: List[KernelReport]):
        pass

    def guess_if_stateful_static(self, report_items: List[KernelReport]) -> bool:
        all_poc_syscall_names = []
        all_calibrate_syscalls = []
        all_guessed_crash_syscalls = set()

        """
        We first collect all PoCs and potential crashed system calls for possibility ranking
        """
        for item in report_items:
            if len(item.guess_crash_syscalls) == 0 and item.call_trace is not None:
                item.guess_crash_syscalls.extend(syscall_resolver.parse_syscall_from_trace(item.call_trace))

            if hasattr(item, 'calibrate_crash_syscalls') and len(item.calibrate_crash_syscalls) == 0:
                item.calibrate_crash_syscalls = self.calibrate_crashed_call_from_poc(item.short_repro,
                                                                                     item.guess_crash_syscalls)

            if item.short_repro is not None and item.short_repro in all_poc_syscall_names:
                continue

            if hasattr(item, 'calibrate_crash_syscalls'):
                all_poc_syscall_names.append(item.short_repro)
                all_calibrate_syscalls.append(item.calibrate_crash_syscalls)

            all_guessed_crash_syscalls.update(item.guess_crash_syscalls)

        for idx in range(len(all_poc_syscall_names)):
            """
            For each PoC, we exam each executed syscall sequence in log, aiming to identify those
            which is possible to crash the kernel and is a sub-sequences of PoC, which indicates the 
            sequence requires certain kernel state as pre-condition to trigger the crash
            """
            cur_calibrate_syscalls = all_calibrate_syscalls[idx]
            cur_poc: str = all_poc_syscall_names[idx]

            print('\nPoC: ', cur_poc)
            print('Calibrated Syscall: ', cur_calibrate_syscalls)

            num_potential_stateful = 0
            num_not_stateful = 0

            for item_idx, item in enumerate(report_items):
                if item.raw_console_log is None or len(item.raw_console_log) == 0:
                    num_not_stateful += 1
                    continue

                suspicious_seqs, seq_match_scores = self.sort_executed_seq_static(item, cur_poc, item.calibrate_crash_syscalls)

                if len(suspicious_seqs) == 0:
                    num_potential_stateful += 1
                    continue

                if max(seq_match_scores) == len(cur_poc.split('-')):
                    num_not_stateful += 1
                    continue

                # sort the remaining sequences with matching score descendingly
                paired_list = list(zip(suspicious_seqs, seq_match_scores))
                sorted_paired_list = sorted(paired_list, key=lambda x: x[1],
                                            reverse=True)

                max_score_elements = [(element, score) for element, score in sorted_paired_list
                                      if score == max(seq_match_scores)]
                print('\n[{}] Max score is'.format(item_idx), max(seq_match_scores),
                      ', potential sequences:', len(sorted_paired_list))
                num_potential_stateful += 1

                for elem_idx, (element, score) in enumerate(max_score_elements):
                    print('\n- Seq [{}] score of executed seq:'.format(elem_idx), score)
                    print('-', parse_sysprog(element))

            print('\nPoC:', cur_poc)
            print('Calibrated Syscall:', cur_calibrate_syscalls)
            print('Potential stateful/not stateful:', str(num_potential_stateful) + '/' + str(num_not_stateful))

    def guess_stateful_execution(self, report_items: List[KernelReport]) -> bool:
        pass


if __name__ == '__main__':
    # crash_item = ReportCrawler()
    # crash_item.console_log_link = 'https://syzkaller.appspot.com/text?tag=CrashLog&x=154633c4880000'
    # crash_item.extract_console_data()
    # crash_item.parse_dump("https://syzkaller.appspot.com/text?tag=CrashReport&x=150819e4880000")
    poc_resolver = PoCResolver()
    print(poc_resolver.find_max_seq_matching(['bpf$MAP_CREATE', 'bpf$BPF_PROG_RAW_TRACEPOINT_LOAD'],
                                             ['bpf$BPF_PROG_RAW_TRACEPOINT_LOAD', 'bpf$BPF_RAW_TRACEPOINT_OPEN']))
    # poc_resolver.extract_suspicious_seq([crash_item])
    # print(crash_item.console_log)
