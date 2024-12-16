import os.path
import sys

from syzbot_crawler import *
from syscall_resolver import *
from poc_resolver import *

poc_resolver = PoCResolver()
dump_resolver = DumpResolver()
syscall_resolver = SyscallResolver()


if __name__ == '__main__':
    if sys.argv[1] == 'crawl':
        crash_array: List[CrashCrawler] = []
        # crawl information of all fixed crashes yet with available reproducer
        if os.path.exists('fixed_crash.json'):
            with open('fixed_crash.json', 'r') as f:
                crash_array = json.loads(f.read(), cls=MyDecoder)
        else:
            crash_array = CrashCrawler.parse_syzbot_tables("fixed")

        # parse the link of each crash
        for idx in range(len(crash_array)):
            syzbot_crash = crash_array[idx]
            print("Processing {}/{}: {} {}".format(idx, len(crash_array), syzbot_crash.title, syzbot_crash.link))
            if syzbot_crash.poc_interval is None:
                time.sleep(1)
                CrashCrawler.parse_crash(syzbot_crash.link)
                json_data = json.dumps(crash_array, cls=CrashListEncoder, indent=4)
                with open("fixed_crash.json", "w") as file:
                    file.write(json_data)

    elif sys.argv[1] == 'analyze':
        crash_array: List[CrashCrawler] = []
        crashed_when_syscalls: List[int] = []

        with open('fixed_crash.json', 'r') as f:
            crash_array.extend(json.loads(f.read(), cls=MyDecoder))

        num_crash_syscall = 0
        num_crash_interrupt = 0
        num_crash_backthread = 0
        num_crash_exiting = 0
        num_tot_crash = 0

        for crash in crash_array:
            for item in crash.report_items:
                if item.report is not None:
                    # use regex match to obtain call trace from raw dump
                    item.call_trace = dump_resolver.parse_call_trace(item.report)
                    item.crash_syscalls.extend(syscall_resolver.parse_syscall_from_trace(item.call_trace))

                if item.syz_repro is not None:
                    item.syscall_names = parse_sysprog(item.syz_repro)

                if item.call_trace is None:
                    continue
                if item.syscall_names is None:
                    continue
                if dump_resolver.if_call_trace_from_syscall(item.call_trace):
                    if len(item.crash_syscalls) != 0:
                        item.calibrate_crash_syscalls = poc_resolver.calibrate_crashed_call_from_poc(
                            item.syscall_names,
                            item.crash_syscalls)
                    else:
                        print('Cannot resolve crashed syscall')
                        print(item.call_trace)

        for idx, syzbot_crash in enumerate(crash_array):
            # parse call trace
            print('Processing {}/{}: {}, {}'.format(idx, len(crash_array), syzbot_crash.title, syzbot_crash.link))

            found_report = False
            for item in syzbot_crash.report_items:
                if item.call_trace is None:
                    continue

                found_report = True
                if dump_resolver.if_call_trace_from_forked(item.call_trace):
                    print('Found background thread related call trace', item.report_link)
                    num_crash_backthread += 1
                    break
                elif dump_resolver.if_call_trace_from_interrupt(item.call_trace):
                    print('Found interrupt related call trace', item.report_link)
                    num_crash_interrupt += 1
                    break
                elif dump_resolver.if_call_trace_exit_mode(item.call_trace):
                    print('Found exit to user mode related call trace', item.report_link)
                    num_crash_exiting += 1
                    break
                elif dump_resolver.if_call_trace_from_syscall(item.call_trace):
                    print('Found syscall related call trace', item.report_link)
                    num_crash_syscall += 1

                    crashed_when_syscalls.append(idx)
                    print(item.call_trace)
                    print('Crashed Syscall:', item.crash_syscalls)
                    print('Calibrated Syscall: ', item.calibrate_crash_syscalls)

                    if len(item.crash_syscalls) == 1:
                        print('Single Crashed Syscall!!!')
                    if len(item.calibrate_crash_syscalls) == 1:
                        print('Correct Infer Syscall!!!')
                    break

                else:
                    print('Unknown call trace', item.report_link)
                    print(item.call_trace)
                    break

            for item in syzbot_crash.report_items:
                if item.syscall_names is None or len(item.syscall_names) == 0:
                    continue
                print('PoC: ', item.syscall_names)

            if found_report:
                num_tot_crash += 1
            else:
                print('Cannot find call trace, please manually check', syzbot_crash.link)

            print()

        print('Crash Call Trace Related to System Call: {}/{}/{}'.format(num_crash_syscall, num_tot_crash,
                                                                         len(crash_array)))
        print('Crash Call Trace Related to Background Thread: {}/{}/{}'.format(num_crash_backthread, num_tot_crash,
                                                                               len(crash_array)))
        print('Crash Call Trace Related to Exiting To User Mode: {}/{}/{}'.format(num_crash_exiting, num_tot_crash,
                                                                                  len(crash_array)))
        print('Crash Call Trace Related to Interrupt: {}/{}/{}'.format(num_crash_interrupt, num_tot_crash,
                                                                       len(crash_array)))
        print()

        if not os.path.exists('fixed_crashes'):
            os.makedirs('fixed_crashes')

        for num, idx in enumerate(crashed_when_syscalls):
            crash: CrashCrawler = crash_array[idx]
            print('Processing {}/{}: {}, {}'.format(num, len(crashed_when_syscalls), crash.title, crash.link))

            data_directory = os.path.join('fixed_crashes', crash.link[crash.link.find('=') + 1:])
            if not os.path.exists(data_directory):
                os.makedirs(data_directory)

            for item in crash.report_items:
                if item.console_log is None:
                    item.extract_console_data()

            poc_resolver.extract_suspicious_seq(crash.report_items)
            json_data = json.dumps(crash, cls=CrashListEncoder, indent=4)

            with open(os.path.join(data_directory, "crash_console.json"), "w") as file:
                file.write(json_data)
    elif sys.argv[1] == 'guess':
        crash_array: List[CrashCrawler] = []
        for dirpath, dirnames, files in os.walk('./fixed_crashes'):
            # Check if the target file is in the current directory's files list
            if 'crash_console.json' in files:
                file_path = os.path.join(dirpath, 'crash_console.json')
                # Open and load the JSON file
                with open(file_path, 'r') as file:
                    crash = json.loads(file.read(), cls=CrashListDecoder)
                    print('\nProcessing {}: {}, {}'.format(len(crash_array), crash.title, crash.link))
                    poc_resolver.guess_if_stateful(crash.report_items)
                    crash_array.append(crash)
