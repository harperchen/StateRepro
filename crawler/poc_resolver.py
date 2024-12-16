"""
Locate crashed syscall trace from console log based on several clue:
1. crashed syscall name
2. hints about previous executed syscalls
"""
from syzbot_crawler import ReportCrawler
from syscall_resolver import SyscallResolver
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

    def extract_suspicious_seq(self, report_items: List[ReportCrawler]):
        for item_i in report_items:
            if item_i.console_log is None or len(item_i.console_log) == 0:
                continue

            suspicious_seqs = set()
            for idx, executed_seq in enumerate(item_i.console_log.split('\n\n')):
                is_crash_seq = False
                for item_j in report_items:
                    short_seq = parse_sysprog(executed_seq)
                    if len(item_j.calibrate_crash_syscalls) != 0:
                        is_crash_seq = self.locate_crashed_sequence(short_seq,
                                                                    item_j.calibrate_crash_syscalls)
                    elif len(item_j.crash_syscalls) != 0:
                        is_crash_seq = self.locate_crashed_sequence(short_seq,
                                                                    item_j.crash_syscalls)
                    else:
                        continue

                    if is_crash_seq:
                        break

                if is_crash_seq:
                    suspicious_seqs.add(executed_seq)

            if len(suspicious_seqs) == 0:
                item_i.console_log = ''
            else:
                item_i.console_log = '\n\n'.join(list(suspicious_seqs))
            print(f'Find {len(suspicious_seqs)} in current crash console log', item_i.console_log_link)

    def guess_if_stateful(self, report_items: List[ReportCrawler]) -> bool:
        poc_syscall_names = []
        calibrate_syscalls = []
        guess_crash_syscalls = []
        """
        We first collect all PoCs
        """
        for item in report_items:
            if len(item.crash_syscalls) == 0 and item.call_trace is not None:
                item.crash_syscalls.extend(syscall_resolver.parse_syscall_from_trace(item.call_trace))

            if item.syscall_names is not None:
                item.calibrate_crash_syscalls = self.calibrate_crashed_call_from_poc(item.syscall_names,
                                                                                     item.crash_syscalls)
            else:
                continue

            if item.syscall_names in poc_syscall_names:
                continue

            poc_syscall_names.append(item.syscall_names)
            calibrate_syscalls.append(item.calibrate_crash_syscalls)
            guess_crash_syscalls.append(item.crash_syscalls)

        for idx, poc in enumerate(poc_syscall_names):
            """
            For each PoC, we exam each executed syscall sequence in log, aiming to identify those
            which is possible to crash the kernel and is a sub-sequences of PoC, which indicates the 
            sequence requires certain kernel state as pre-condition to trigger the crash
            """
            print('\nPoC: ', poc)
            print('Guessed Crashed Syscall: ', guess_crash_syscalls[idx])
            print('Calibrated Syscall: ', calibrate_syscalls[idx])
            num_potential_stateful = 0
            num_not_stateful = 0

            for item in report_items:
                if item.console_log is None:
                    item.extract_console_data()
                if item.console_log is None or len(item.console_log) == 0:
                    continue

                suspicious_seqs = []
                seq_match_scores = []
                suspicious_short_seqs = []

                for seq in item.console_log.split('\n\n'):
                    find_crashed_call = False
                    executed_seq = parse_sysprog(seq).split('-')
                    for crash_call in calibrate_syscalls[idx]:
                        if crash_call in executed_seq:
                            find_crashed_call = True
                            break
                    if not find_crashed_call:
                        continue

                    if seq in suspicious_seqs:
                        continue

                    if executed_seq in suspicious_short_seqs:
                        continue
                    _, match_score = self.find_max_seq_matching(executed_seq, poc.split('-'))
                    seq_match_scores.append(match_score)
                    suspicious_seqs.append(seq)
                    suspicious_short_seqs.append(executed_seq)

                if len(suspicious_seqs) == 0:
                    print('!!! Cannot find any suspicious seq in console log: ', item.console_log_link)
                    continue

                max_score = max(seq_match_scores)
                if max_score == len(poc.split('-')):
                    # print('The whole trace is in log, cannot be stateful', item.console_log_link)
                    num_not_stateful += 1
                    continue

                paired_list = list(zip(suspicious_seqs, seq_match_scores))

                sorted_paired_list = sorted(paired_list, key=lambda x: x[1],
                                            reverse=True)  # Use reverse=True for descending order

                max_score_elements = [(element, score) for element, score in sorted_paired_list if score == max_score]
                print('- Max score is', max_score, ', potential sequences:', len(sorted_paired_list), 'in',
                      item.console_log_link)
                num_potential_stateful += 1
                for element, score in max_score_elements:
                    print('\nscore of executed seq:', score, 'in', item.console_log_link)
                    print(element)
            print('Potential stateful', num_potential_stateful)
            print('Potential not stateful', num_not_stateful)


if __name__ == '__main__':
    crash_item = ReportCrawler()
    crash_item.console_log_link = 'https://syzkaller.appspot.com/text?tag=CrashLog&x=154633c4880000'
    crash_item.extract_console_data()
    crash_item.parse_dump("https://syzkaller.appspot.com/text?tag=CrashReport&x=150819e4880000")
    poc_resolver = PoCResolver()
    poc_resolver.extract_suspicious_seq([crash_item])
    print(crash_item.console_log)
