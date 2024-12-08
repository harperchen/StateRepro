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
__dump_stack lib/dump_stack.c:88 [inline]
dump_stack_lvl+0xd9/0x1b0 lib/dump_stack.c:106
print_address_description mm/kasan/report.c:364 [inline]
print_report+0xc4/0x620 mm/kasan/report.c:475
kasan_report+0xda/0x110 mm/kasan/report.c:588
read_descriptors+0x27e/0x290 drivers/usb/core/sysfs.c:883
sysfs_kf_bin_read+0x1a0/0x270 fs/sysfs/file.c:97
kernfs_file_read_iter fs/kernfs/file.c:251 [inline]
kernfs_fop_read_iter+0x37c/0x680 fs/kernfs/file.c:280
call_read_iter include/linux/fs.h:1865 [inline]
new_sync_read fs/read_write.c:389 [inline]
vfs_read+0x4e0/0x930 fs/read_write.c:470
ksys_read+0x12f/0x250 fs/read_write.c:613
do_syscall_x64 arch/x86/entry/common.c:50 [inline]
do_syscall_64+0x38/0xb0 arch/x86/entry/common.c:80
entry_SYSCALL_64_after_hwframe+0x63/0xcd
    """
    print(resolver.parse_syscall_from_trace(call_trace))
