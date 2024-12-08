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
            elif line.startswith('ksys_'):
                if '+' in line:
                    crashed_syscall = line[5:line.find('+')]
                else:
                    crashed_syscall = line[5:line.find(' ')]
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
                candidate_syscalls.update(self.kernel_func_to_syscall[func_name])
                break

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
                    candidate_syscalls.update(calls)
                break

        if len(candidate_syscalls) == 0:
            return self.parse_syscall_from_trace_manually(call_trace)
        return list(candidate_syscalls)


def reformat_csv():
    # Load the CSV file, ensuring proper handling of commas within quotes
    df = pd.read_csv('./mysyzdirect/syscall_kernel_map.csv', header=None,
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
        """
 bpf_migrate_filter net/core/filter.c:1069 [inline]
 bpf_prepare_filter+0xb65/0x1060 net/core/filter.c:1117
 __get_filter+0x1e0/0x280 net/core/filter.c:1310
 sk_attach_filter+0x1d/0x90 net/core/filter.c:1325
 tun_attach_filter drivers/net/tun.c:2765 [inline]
 __tun_chr_ioctl+0x1198/0x4420 drivers/net/tun.c:3113
 tun_chr_ioctl+0x2a/0x40 drivers/net/tun.c:3161
 vfs_ioctl fs/ioctl.c:46 [inline]
 file_ioctl fs/ioctl.c:500 [inline]
 do_vfs_ioctl+0x1cf/0x16a0 fs/ioctl.c:684
 ksys_ioctl+0xa9/0xd0 fs/ioctl.c:701
 __do_sys_ioctl fs/ioctl.c:708 [inline]
 __se_sys_ioctl fs/ioctl.c:706 [inline]
 __x64_sys_ioctl+0x73/0xb0 fs/ioctl.c:706
 do_syscall_64+0x1b1/0x800 arch/x86/entry/common.c:287
 entry_SYSCALL_64_after_hwframe+0x49/0xbe
    """
    print(resolver.parse_syscall_from_trace(call_trace))
