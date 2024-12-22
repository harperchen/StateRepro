"""
Guess crashed syzkaller call from crash call trace
"""

import json
import pandas as pd


class SyscallResolver:
    def __init__(self) -> None:
        with open('/home/weichen/StateRepro/crawler/mysyzdirect/myKernelCode2Syscall.json', 'r') as f:
            self.kernel_to_syscall_syzdirect = json.load(f)

        csv_data = pd.read_csv('/home/weichen/StateRepro/crawler/mysyzdirect/syscall_kernel_map.csv', header=None,
                               names=['Syscall', 'Kernelfunc'], na_values='', keep_default_na=False)
        csv_data.fillna('', inplace=True)
        self.kernel_func_to_syscall = {}
        for index, row in csv_data.iterrows():
            kernel_funcs = row['Kernelfunc']
            syscall = row['Syscall']

            for func in kernel_funcs.split(','):
                if func not in self.kernel_func_to_syscall:
                    self.kernel_func_to_syscall[func] = []
                self.kernel_func_to_syscall[func].append(syscall)

        with open('/home/weichen/StateRepro/crawler/mysyzdirect/syzcall_to_syscall.json', 'r') as f:
            syzcall_to_syscall = json.load(f)

        self.syscall_to_syzcall = {}
        for syzcall in syzcall_to_syscall:
            for syscall in syzcall_to_syscall[syzcall]:
                if syscall not in self.syscall_to_syzcall:
                    self.syscall_to_syzcall[syscall] = set()
                self.syscall_to_syzcall[syscall].add(syzcall)

    @staticmethod
    def two_custom_intersection(set1, set2):
        result = set()
        for str1 in set1:
            for str2 in set2:
                if str1.startswith(str2 + '$'):
                    result.add(str1)
                elif str2.startswith(str1 + '$'):
                    result.add(str2)
                else:
                    result.add(str1)
                    result.add(str2)
        if len(set1) == 0:
            return set2
        if len(set2) == 0:
            return set1
        return result

    @staticmethod
    def common_prefix(strings):
        if not strings:
            return ''

        # Find the shortest string in the set
        shortest = min(strings, key=len)

        # Iterate over characters in the shortest string
        for i, char in enumerate(shortest):
            for string in strings:
                if string[i] != char:
                    return shortest[:i]

        # If all characters match, return the entire shortest string
        return shortest

    @staticmethod
    def custom_intersection(*sets):
        if len(sets) == 0:
            return set()

        # Custom intersection logic
        result = sets[0]
        for s in sets[1:]:
            # Replace the line below with your custom logic
            result = SyscallResolver.two_custom_intersection(result, s)

        return result

    """
    syscall1 involves syscall2?
    """
    def if_one_call_involve_another(self, syscall1: str, syscall2: str) -> bool:
        if '$' in syscall2:
            primitive_syscall2 = syscall2[:syscall2.find('$')]
        else:
            primitive_syscall2 = syscall2

        if '$' in syscall1:
            primitive_syscall1 = syscall1[:syscall1.find('$')]
        else:
            primitive_syscall1 = syscall1

        if primitive_syscall2 not in self.syscall_to_syzcall:
            return False

        if primitive_syscall1 not in self.syscall_to_syzcall[primitive_syscall2]:
            return False

        return True

    """
    Given two syscall, compute their match score
    """
    def compute_match_score(self, syscall1: str, syscall2: str) -> float:
        if syscall1 == syscall2:
            return 1

        if '$' in syscall1 and '$' not in syscall2:
            primitive_call1 = syscall1[:syscall1.find('$')]
            if primitive_call1 == syscall2:
                return 0.5
            elif self.if_one_call_involve_another(primitive_call1, syscall2):
                return 0.3
            else:
                return 0
        elif '$' not in syscall1 and '$' in syscall2:
            primitive_call2 = syscall2[:syscall2.find('$')]
            if primitive_call2 == syscall1:
                return 0.5
            elif self.if_one_call_involve_another(syscall1, primitive_call2):
                return 0.3
            else:
                return 0

        elif '$' in syscall1 and '$' in syscall2:
            primitive_call1 = syscall1[:syscall1.find('$')]
            primitive_call2 = syscall2[:syscall2.find('$')]

            if primitive_call1 != primitive_call2:
                if self.if_one_call_involve_another(primitive_call1, primitive_call2):
                    return 0.3
                else:
                    return 0
            else:
                return 0.5
        else:
            if self.if_one_call_involve_another(syscall1, syscall2):
                return 0.3
            else:
                return 0

    def parse_syscall_from_trace(self, call_trace: str, precise=True) -> []:
        potential_calls = set()
        potential_calls.update(self.parse_syscall_from_trace_manually(call_trace))
        if precise:
            # potential_calls.update(self.parse_syscall_from_trace_via_syzdirect(call_trace))
            potential_calls = self.two_custom_intersection(potential_calls,
                                                           self.parse_syscall_from_trace_via_written_map(call_trace))

        return list(potential_calls)

    def parse_syscall_from_trace_manually(self, call_trace: str) -> []:
        """
        given a call trace, find the related syscall that trigger the crash
        """
        crashed_syscall = ''
        candidate_syscalls = set()
        for line in reversed(call_trace.split('\n')):
            line = line.strip()
            if line.startswith('SyS_'):
                crashed_syscall = line[4:line.find('+')]
                break
            elif line.startswith('compat_SyS_'):
                crashed_syscall = line[11:line.find('+')]
                break
            elif line.startswith('__x64_sys_'):
                crashed_syscall = line[10:line.find('+')]
                break
            elif line.startswith('__do_sys_'):
                if '+' in line:
                    crashed_syscall = line[9:line.find('+')]
                else:
                    crashed_syscall = line[9:line.find(' ')]
                break
            elif line.startswith('__do_compat_sys_'):
                if '+' in line:
                    crashed_syscall = line[16:line.find('+')]
                else:
                    crashed_syscall = line[16:line.find(' ')]
            elif line.startswith('__sys_'):
                crashed_syscall = line[6:line.find('+')]
                break
            elif line.startswith('__arm64_sys_'):
                crashed_syscall = line[12:line.find('+')]
                break
            elif line.startswith('__arm64_compat_sys_'):
                crashed_syscall = line[19: line.find('+')]
                break

        if crashed_syscall != '':
            candidate_syscalls.add(crashed_syscall)
            if crashed_syscall in self.syscall_to_syzcall:
                candidate_syscalls.update(self.syscall_to_syzcall[crashed_syscall])
        return list(candidate_syscalls)

    def parse_syscall_from_trace_via_written_map(self, call_trace: str) -> []:
        call_trace.strip()
        candidate_syscalls = set()
        for line in call_trace.split('\n'):
            line = line.strip()
            if line == '':
                continue
            func_name = line.split()[0]
            if '+' in func_name:
                func_name = func_name[:func_name.find('+')]
            if func_name.endswith('.cold'):
                func_name = func_name[:func_name.find('.cold')]
            if '.constprop' in func_name:
                func_name = func_name[:func_name.find('.constprop')]
            if '.isra.' in func_name:
                func_name = func_name[:func_name.find('.isra.')]
            if func_name in self.kernel_func_to_syscall:
                for syscall in self.kernel_func_to_syscall[func_name]:
                    candidate_syscalls.add(syscall)
                    if '$' in syscall:
                        primitive_call = syscall[:syscall.find('$')]
                    else:
                        primitive_call = syscall
                    if primitive_call in self.syscall_to_syzcall:
                        candidate_syscalls.update(self.syscall_to_syzcall[primitive_call])

        if len(candidate_syscalls) == 0:
            return self.parse_syscall_from_trace_manually(call_trace)
        return list(candidate_syscalls)

    def parse_syscall_from_trace_via_syzdirect(self, call_trace: str) -> []:
        call_trace.strip()
        candidate_syscalls = set()
        for line in call_trace.split('\n'):
            line = line.strip()
            if line == '':
                continue
            func_name = line.split()[0]
            if '+' in func_name:
                func_name = func_name[:func_name.find('+')]
            if func_name.endswith('.cold'):
                func_name = func_name[:func_name.find('.cold')]
            if '.constprop' in func_name:
                func_name = func_name[:func_name.find('.constprop')]
            if '.isra.' in func_name:
                func_name = func_name[:func_name.find('.isra.')]
            if func_name in self.kernel_to_syscall_syzdirect:
                bb_to_syscall = self.kernel_to_syscall_syzdirect[func_name]
                for bb_id, calls in bb_to_syscall.items():
                    for syscall in calls:
                        candidate_syscalls.add(syscall)
                        if '$' in syscall:
                            primitive_call = syscall[:syscall.find('$')]
                        else:
                            primitive_call = syscall
                        if primitive_call in self.syscall_to_syzcall:
                            candidate_syscalls.update(self.syscall_to_syzcall[primitive_call])

        if len(candidate_syscalls) == 0:
            return self.parse_syscall_from_trace_manually(call_trace)
        return list(candidate_syscalls)


def reformat_csv():
    # Load the CSV file, ensuring proper handling of commas within quotes
    df = pd.read_csv('../mysyzdirect/syscall_kernel_map.csv', header=None,
                     names=['Syscall', 'Kernelfunc'], na_values='', keep_default_na=False)

    # Replace NaN values with an empty string
    df.fillna('', inplace=True)

    # Split the 'Kernelfunc' into a list, remove duplicates, and join them back with commas
    df_grouped = df.groupby('Syscall')['Kernelfunc'].apply(
        lambda x: ','.join(set(','.join(x).split(',')))).reset_index()

    # Sort the dataframe by 'Syscall'
    df_sorted = df_grouped.sort_values(by='Syscall')

    # Output to a new CSV file, ensuring quotes are used when needed
    df_sorted.to_csv('output.csv', index=False)


if __name__ == '__main__':
    # reformat_csv()
    resolver = SyscallResolver()
    call_trace = \
        """add_new_free_space+0x290/0x294 fs/btrfs/block-group.c:537\nbtrfs_make_block_group+0x34c/0x87c fs/btrfs/block-group.c:2712\ncreate_chunk fs/btrfs/volumes.c:5441 [inline]\nbtrfs_create_chunk+0x142c/0x1ea4 fs/btrfs/volumes.c:5527\ndo_chunk_alloc fs/btrfs/block-group.c:3710 [inline]\nbtrfs_chunk_alloc+0x69c/0xf00 fs/btrfs/block-group.c:4004\nfind_free_extent_update_loop fs/btrfs/extent-tree.c:4024 [inline]\nfind_free_extent+0x43bc/0x5334 fs/btrfs/extent-tree.c:4407\nbtrfs_reserve_extent+0x35c/0x674 fs/btrfs/extent-tree.c:4500\n__btrfs_prealloc_file_range+0x2a8/0x1000 fs/btrfs/inode.c:9594\nbtrfs_prealloc_file_range+0x60/0x7c fs/btrfs/inode.c:9688\nbtrfs_fallocate+0x1644/0x19e4 fs/btrfs/file.c:3177\nvfs_fallocate+0x478/0x5b4 fs/open.c:324\nksys_fallocate fs/open.c:347 [inline]\n__do_sys_fallocate fs/open.c:355 [inline]\n__se_sys_fallocate fs/open.c:353 [inline]\n__arm64_sys_fallocate+0xc0/0x110 fs/open.c:353\n__invoke_syscall arch/arm64/kernel/syscall.c:38 [inline]\ninvoke_syscall+0x98/0x2c0 arch/arm64/kernel/syscall.c:52\nel0_svc_common+0x138/0x258 arch/arm64/kernel/syscall.c:142\ndo_el0_svc+0x64/0x198 arch/arm64/kernel/syscall.c:193\nel0_svc+0x4c/0x15c arch/arm64/kernel/entry-common.c:637\nel0t_64_sync_handler+0x84/0xf0 arch/arm64/kernel/entry-common.c:655\nel0t_64_sync+0x190/0x194 arch/arm64/kernel/entry.S:591
    """
    print(resolver.parse_syscall_from_trace(call_trace))
