"""
Locate crashed syscall trace from console log based on several clue:
1. crashed syscall name
2. hints about previous executed syscalls
"""

from syzbot_crawler import ReportCrawler
from syscall_resolver import SyscallResolver
from typing import List

syscall_resolver = SyscallResolver()


class PoCResolver:
    def __init__(self):
        self.num_crashed_call_correct = 0
        self.num_crashed_primitive_correct = 0

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

    def locate_crashed_sequence(self, sequence: str, crash_calls: List[str]) -> bool:
        """
        TODO: more fine-grained matching, currently we do not consider subsystem,
        say, only ioctl is consider, while ioctl$XX is not considered
        """
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
        # dp[i][j] 表示在考虑 arr1[0:i] 和 arr2[0:j] 时的最大匹配得分
        dp = [[0] * (m + 1) for _ in range(n + 1)]

        # 用于回溯最优匹配
        parent = [[None] * (m + 1) for _ in range(n + 1)]

        for i in range(1, n + 1):
            for j in range(1, m + 1):
                # 这里不再考虑不匹配情况，只在有分数时更新
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])  # 保持之前的最优值

                # 计算匹配得分
                score = syscall_resolver.compute_match_score(arr1[i - 1], arr2[j - 1])
                if score > 0 and dp[i - 1][j - 1] + score > dp[i][j]:
                    dp[i][j] = dp[i - 1][j - 1] + score
                    parent[i][j] = (i - 1, j - 1)
                else:
                    if dp[i - 1][j] > dp[i][j - 1]:
                        parent[i][j] = (i - 1, j)
                    else:
                        parent[i][j] = (i, j - 1)

        # 回溯找到匹配对
        matches = []
        i, j = n, m
        while i > 0 and j > 0:
            pi, pj = parent[i][j]
            if pi == i - 1 and pj == j - 1 and syscall_resolver.compute_match_score(arr1[pi], arr2[pj]) > 0:
                matches.append((pi, pj))
            i, j = pi, pj

        matches.reverse()  # 确保匹配是从小到大的顺序
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
        for item in report_items:
            if item.console_log is None:
                item.extract_console_data()
            if item.console_log is None or len(item.console_log) == 0:
                continue

            suspicious_seqs = set()
            for executed_seq in item.console_log.split('\n\n'):
                is_crash_seq = False
                for item in report_items:
                    if len(item.calibrate_crash_syscalls) != 0:
                        is_crash_seq = self.locate_crashed_sequence(self.parse_sysprog(executed_seq),
                                                                    item.calibrate_crash_syscalls)
                    elif len(item.crash_syscalls) != 0:
                        is_crash_seq = self.locate_crashed_sequence(self.parse_sysprog(executed_seq),
                                                                    item.crash_syscalls)
                    else:
                        continue

                    if is_crash_seq:
                        break
                if is_crash_seq:
                    suspicious_seqs.add(executed_seq)

            if len(suspicious_seqs) == 0:
                item.console_log = ''
            else:
                item.console_log = '\n\n'.join(list(suspicious_seqs))

            print(f'Find {len(suspicious_seqs)} in current crash console log')

    def guess_if_stateful(self, report_items: List[ReportCrawler]) -> bool:
        poc_syscall_names = []
        calibrate_syscalls = []
        for item in report_items:
            if item.syscall_names is None:
                continue

            if len(item.crash_syscalls) == 0 and item.call_trace is not None:
                item.crash_syscalls.extend(syscall_resolver.parse_syscall_from_trace(item.call_trace))
                item.calibrate_crash_syscalls = self.calibrate_crashed_call_from_poc(item.syscall_names,
                                                                                     item.crash_syscalls)
            if item.syscall_names in poc_syscall_names:
                continue

            poc_syscall_names.append(item.syscall_names)
            calibrate_syscalls.append(item.calibrate_crash_syscalls)

        for idx, poc in enumerate(poc_syscall_names):
            print('\nPoC: ', poc)
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
                for seq in item.console_log.split('\n\n'):
                    find_crashed_call = False
                    executed_seq = self.parse_sysprog(seq).split('-')
                    for crash_call in calibrate_syscalls[idx]:
                        if crash_call in executed_seq:
                            find_crashed_call = True
                            break
                    if not find_crashed_call:
                        continue

                    _, match_score = self.find_max_seq_matching(executed_seq, poc.split('-'))
                    seq_match_scores.append(match_score)
                    suspicious_seqs.append(seq)

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
                print('- Max score is', max_score, ', potential sequences:', len(sorted_paired_list), 'in', item.console_log_link)
                num_potential_stateful += 1
                # for element, score in max_score_elements:
                #     print('\nscore of executed seq:', score, 'in', item.console_log_link)
                #     print(element)
            print('Potential stateful', num_potential_stateful)
            print('Potential not stateful', num_not_stateful)
