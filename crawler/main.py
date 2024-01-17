import os.path
import re
import json
import sys
import time
import requests
import pandas as pd

from syscall import *
from patterns import *

from typing import List
from bs4 import BeautifulSoup
from datetime import datetime
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

code2Syscall = kernel2Syscall()

class CommitInfo:
    def __init__(self, time, commit,
                 console_log=None, console_log_link=None,
                 report=None, report_link=None,
                 syz_repro=None, syz_repro_link=None,
                 call_trace=None, syscall_names=None):
        self.time = time
        self.commit = commit

        self.console_log = console_log
        self.console_log_link = console_log_link

        self.report = report
        self.report_link = report_link

        self.syz_repro = syz_repro
        self.syz_repro_link = syz_repro_link

        self.call_trace = call_trace
        self.syscall_names = syscall_names

    def parse_report(self, report_cell):
        """
        parse crash report from url
        """
        if report_cell.find('a') is not None:
            report_link = "https://syzkaller.appspot.com" + report_cell.find('a')['href']
            time.sleep(1)
            session = requests.Session()
            retry = Retry(connect=3, backoff_factor=0.5)
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            response = session.get(report_link)
            report_data = response.text
            if '------------[ cut here ]------------' in report_data:
                idx = report_data.find('------------[ cut here ]------------')
                report_data = report_data[idx:]

            self.report_link = report_link
            self.report = report_data

    def parse_console_log(self, console_cell):
        """
        just record console log link, we parse it later
        """
        console_name = console_cell.get_text().strip()
        if console_name == 'strace log':
            console_link = ''
            console_data = None
        else:
            # TODO: currently we do not analyze console log
            console_link = "https://syzkaller.appspot.com" + console_cell.find('a')['href']
            # too large, temporarily not store
            console_data = None

        self.console_log_link = console_link
        self.console_log = console_data

    def extract_console_data(self):
        """
        parse all syz programs recorded in execution log
        """
        if self.console_log_link == '':
            return

        time.sleep(1)
        session = requests.Session()
        retry = Retry(connect=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        response = session.get(self.console_log_link)
        console_data = response.text

        # extract executed programs
        pattern = "\d{2}:\d{2}:\d{2} executing program \d+:\n"
        p = re.compile(pattern)
        m = p.search(console_data)
        if not m:
            self.console_log = ""
            return

        segments = re.findall(pattern, console_data)
        segments = [segment + console_data.split(segment, 1)[1].split('\n\n', 1)[0] + '\n\n' for segment in segments]
        all_progs = []
        for segment in segments:
            syz_prog = '\n'.join(segment.split('\n')[1:-2])
            syscalls = self.parse_sysprog(syz_prog)
            all_progs.append(syscalls)

        self.console_log = '\n'.join(all_progs)

    def parse_syz_repro(self, syz_repro_cell):
        """
        parse the reproducer for the crash if exists
        """
        if syz_repro_cell.find('a'):
            syz_repro_link = "https://syzkaller.appspot.com" + syz_repro_cell.find('a')['href']
            time.sleep(1)
            session = requests.Session()
            retry = Retry(connect=3, backoff_factor=0.5)
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            response = session.get(syz_repro_link)
            syz_repro_data = response.text

        else:
            syz_repro_data = None
            syz_repro_link = ''

        self.syz_repro = syz_repro_data
        self.syz_repro_link = syz_repro_link

    def parse_deeper(self):
        """
        parse syscall names in reproducer and call trace from report
        """
        if self.syz_repro is not None:
            self.syscall_names = self.parse_sysprog(self.syz_repro)
        self.call_trace = self.parse_call_trace(self.report)
        if self.call_trace == "":
            self.call_trace = None
            print('Warning: cannot find call trace', self.report_link)

    @staticmethod
    def parse_sysprog(syz_prog):
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
    def parse_back_trace(report):
        if 'backtrace:' in report:
            pass

    @staticmethod
    def parse_call_trace(report):
        # TODO: call trace is not parsed so far
        if 'Call trace:\n' in report:
            report = report.replace('Call trace:\n', 'Call Trace:\n')

        if 'Call Trace:\n' not in report:
            return None

        if "WARNING" in report or "GPF" in report or "kernel BUG at" in report \
                or "BUG: unable to handle" in report:
            found = CommitInfo.get_call_trace(warn, report)
            if found:
                # print(found.group(1)+found.group(2))
                return found.group(1) + found.group(2)
            found = CommitInfo.get_call_trace(warn2, report)
            if found:
                # print(found.group(1)+found.group(2))
                return found.group(1) + found.group(2)
            found = CommitInfo.get_call_trace(warn3, report)
            if found:
                # print(found.group(1)+found.group(2))
                return found.group(1) + found.group(2)
            found = CommitInfo.get_call_trace(warn4, report)
            if found:
                # print(found.group(1)+found.group(2))
                return found.group(1) + found.group(2)
        elif "kasan" in report or 'kmsan' in report or 'ubsan' in report:
            found = CommitInfo.get_call_trace(kasan_pattern, report)
            if found:
                # print(found.group(1))
                return found.group(1)
            found = CommitInfo.get_call_trace(kasan_pattern2, report)
            if found:
                # print(found.group(1))
                return found.group(1)
            found = CommitInfo.get_call_trace(kasan_pattern3, report)

        else:
            pass
        found = CommitInfo.get_call_trace(pattern3, report)
        if found:
            return found.group(1)
        found = CommitInfo.get_call_trace(pattern4, report)
        if found:
            return found.group(1) + found.group(2)
        found = CommitInfo.get_call_trace(pattern5, report)
        if found:
            return found.group(1)

        found = CommitInfo.get_call_trace(pattern6, report)
        if found:
            return found.group(1)
        else:
            return ""

    def if_call_trace_from_syscall(self):
        """
        verify if current call trace is related to syscall execution
        """
        if ('do_syscall_x64' in self.call_trace
            or 'do_syscall_64' in self.call_trace
            or 'entry_SYSCALL_64' in self.call_trace) \
                and ('__x64_sys_' in self.call_trace
                     or '__sys_' in self.call_trace
                     or 'SyS_' in self.call_trace
                     or 'ksys_' in self.call_trace):
            # crash is triggered when executing syscall on x86_64
            return True
        elif '__arm64_sys_' in self.call_trace or '__invoke_syscall' in self.call_trace:
            return True
        else:
            return False

    def if_call_trace_from_forked(self):
        """
        verify if current call trace is related to background thread
        """
        if 'ret_from_fork' in self.call_trace or 'process_one_work' in self.call_trace:
            return True
        else:
            return False

    def if_call_trace_from_exited(self):
        if 'syscall_exit_to_user_mode' in self.call_trace or 'exit_to_user_mode' in self.call_trace:
            return True
        else:
            return False

    def if_call_trace_from_interrupt(self):
        return False


class CrashInfo:
    def __init__(self, title, link, subsystem='', crash_items=[], poc_interval=None):
        self.link = link
        if '\n' in title:
            self.title = title.split('\n')[0]
            self.subsystem = '_'.join(title.split('\n')[1:])
        else:
            self.title = title
            self.subsystem = subsystem
        self.crash_items = crash_items
        self.poc_interval = poc_interval

    def add_crash(self, new_crash):
        self.crash_items.append(new_crash)

    def get_first_repro_time(self):
        """
        compute the time interval from first time the crash occur and the time when a reproducer is available
        """
        time_format = "%Y/%m/%d %H:%M"
        time_slots = [datetime.strptime(item.time, time_format) for item in self.crash_items]
        earliest_time_slot = min(time_slots)
        non_none_time_slots = []
        for item in self.crash_items:
            if item.syz_repro is not None:
                non_none_time_slots.append(datetime.strptime(item.time, time_format))
        if len(non_none_time_slots) != 0:
            non_none_earliest_time_slot = min(non_none_time_slots)
            time_interval = non_none_earliest_time_slot - earliest_time_slot
        else:
            time_interval = None
        self.poc_interval = time_interval

    @staticmethod
    def is_sub_array(array1: List[str], array2: List[str]):
        i = 0  # Pointer for array1
        j = 0  # Pointer for array2

        while i < len(array1) and j < len(array2):
            if array1[i].startswith(array2[j]):
                i += 1
            j += 1

        return i == len(array1)  # Return True if all elements of array1 were found in array2

    @staticmethod
    def match_log_repro(log, repro) -> bool:
        """
        TODO: more fine-grained matching, currently we do not consider subsystem, say, only ioctl is consider, while
        ioctl$XX is not considered
        """
        repro_syscalls = repro.split('-')
        for log_item in log.split('\n'):
            log_item_syscalls = log_item.split('-')
            if CrashInfo.is_sub_array(repro_syscalls, log_item_syscalls):
                print("Find matched execution log and reproducer")
                print("Program in execution log:", log_item)
                print("Reproducer:", repro)
                return True
        return False

    @staticmethod
    def can_we_match(call_trace, repro) -> bool:
        """
        If the call trace can be caused by one of the syscall in reproducer
        """
        # the crashed syscall in report might not in reproducer, let's currently omit it
        crashed_syscall = kernel2Syscall.parse_call_trace_from_syscall(call_trace)
        for syscall in repro.split('-'):
            if syscall.startswith(crashed_syscall):
                return True
        return False

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


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, CommitInfo):
            return obj.__dict__  # Convert MyClass object to a dictionary
        elif isinstance(obj, CrashInfo):
            return {
                **obj.__dict__,  # Convert Address object to a dictionary
                "poc_interval": str(obj.poc_interval)
            }
        return super().default(obj)


class MyDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.custom_object_hook, *args, **kwargs)

    def custom_object_hook(self, obj):
        if 'link' in obj and 'title' in obj and 'subsystem' in obj and 'poc_interval' in obj and 'crash_items' in obj:
            crash_items = []
            poc_interval = None
            if obj['poc_interval'] != 'None':
                poc_interval = pd.Timedelta(obj['poc_interval'])
            for commit in obj['crash_items']:
                syscall_names = commit.get('syscall_names', [])
                crash_items.append(CommitInfo(commit['time'],
                                              commit['commit'],
                                              commit['console_log'],
                                              commit['console_log_link'],
                                              commit['report'],
                                              commit['report_link'],
                                              commit['syz_repro'],
                                              commit['syz_repro_link'],
                                              commit['call_trace'],
                                              syscall_names))
            return CrashInfo(obj['title'], obj['link'], obj['subsystem'], crash_items, poc_interval)
        return obj


def parse_fixed():
    crash_arr: list[CrashInfo] = []
    url = 'https://syzkaller.appspot.com/upstream/fixed'
    response = requests.get(url)

    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find the table element
    table = soup.find('table', class_='list_table')

    # Find the index of the "Repro" column header
    headers = table.find_all('th')
    repro_index = [i for i, header in enumerate(headers) if header.get_text().strip() == 'Repro'][0]

    # Verify "Repro" column and retrieve data from "Title" column
    title_index = [i for i, header in enumerate(headers) if header.get_text().strip() == 'Title'][0]
    rows = table.find_all('tr')

    num_tot_crashes = 0
    num_with_repro = 0
    for row in rows:
        cells = row.find_all('td')
        if len(cells) > repro_index:
            num_tot_crashes += 1
            if cells[repro_index].get_text().strip() == 'syz' or cells[repro_index].get_text().strip() == 'C':
                num_with_repro += 1
                if len(cells) > title_index:
                    title_cell = cells[title_index]
                    title = title_cell.get_text().strip()
                    if 'lock' in title or 'KCSAN' in title:
                        continue
                    link = title_cell.find('a')['href']
                    crash = CrashInfo(title, "https://syzkaller.appspot.com" + link)
                    crash_arr.append(crash)
    print('Total Fixed Crashes: ', len(rows))
    print('Total Crashes with Repro: ', num_with_repro)
    print('Total Crashes with Repro but Not Data Race: ', len(crash_arr))
    return crash_arr


def parse_crash(crash: CrashInfo):
    time.sleep(1)
    response = requests.get(crash.link)
    soup = BeautifulSoup(response.content, 'html.parser')
    table = None
    for tbl in soup.find_all('table'):
        caption = tbl.find('caption')
        if caption and caption.get_text().strip().startswith('Crashes'):
            table = tbl
            break

    if table is None:
        print(response.text)
        exit(0)

    # Find the index of the "Syz repro" and "C repro" column headers
    headers = table.find_all('th')
    time_index = [i for i, header in enumerate(headers) if header.get_text().strip() == 'Time'][0]
    commit_index = [i for i, header in enumerate(headers) if header.get_text().strip() == 'Commit'][0]
    console_index = [i for i, header in enumerate(headers) if header.get_text().strip() == 'Log'][0]
    report_index = [i for i, header in enumerate(headers) if header.get_text().strip() == 'Report'][0]
    syz_repro_index = [i for i, header in enumerate(headers) if header.get_text().strip() == 'Syz repro'][0]
    c_repro_index = [i for i, header in enumerate(headers) if header.get_text().strip() == 'C repro'][0]

    # Retrieve data from the "Syz repro" and "C repro" columns
    rows = table.find_all('tr')
    for row in rows:
        cells = row.find_all('td')
        if len(cells) > syz_repro_index and len(cells) > c_repro_index:
            item_time = cells[time_index].get_text().strip()
            commit = cells[commit_index].get_text().strip()
            cur_item = CommitInfo(item_time, commit)

            cur_item.parse_report(cells[report_index])
            cur_item.parse_console_log(cells[console_index])
            cur_item.parse_syz_repro(cells[syz_repro_index])

            crash.add_crash(cur_item)
    crash.get_first_repro_time()


if __name__ == '__main__':

    if sys.argv[1] == '0':
        # parse a specific crash
        parse_crash(crash=CrashInfo('',
                                    link='https://syzkaller.appspot.com/bug?id=5270676317f74d30265abb76b7ca58b5608ca545'))

    elif sys.argv[1] == '1':
        # crawl information of all fixed crashes yet with available reproducer
        crash_arr = None
        if os.path.exists('fixed_crash.json'):
            with open('fixed_crash.json', 'r') as f:
                crash_arr = json.loads(f.read(), cls=MyDecoder)

        else:
            crash_arr = parse_fixed()

        # parse the link of each crash
        for idx, crash in enumerate(crash_arr):
            print("Processing {}/{}: {} {}".format(idx, len(crash_arr), crash.title, crash.link))
            if crash.poc_interval is None:
                time.sleep(1)
                parse_crash(crash)
                json_data = json.dumps(crash_arr, cls=MyEncoder, indent=4)
                with open("fixed_crash.json", "w") as file:
                    file.write(json_data)
    elif sys.argv[1] == '2':
        crash_arr = []
        crash_arr_syscall = []

        with open('fixed_crash.json', 'r') as f:
            crash_arr = json.loads(f.read(), cls=MyDecoder)

        num_crash_syscall = 0
        num_crash_interrupt = 0
        num_crash_backthread = 0
        num_crash_exiting = 0
        num_tot_crash = 0

        for idx, crash in enumerate(crash_arr):
            # parse call trace
            print('Processing {}/{}: {}, {}'.format(idx, len(crash_arr), crash.title, crash.link))

            found_report = False
            for item in crash.crash_items:
                if item.report is not None:
                    item.parse_deeper()
                    if item.call_trace is not None:
                        found_report = True

            found_item = None
            for item in crash.crash_items:
                if item.call_trace is not None:
                    if item.if_call_trace_from_syscall():
                        found_item = item
                        print('Found syscall related call trace', item.report_link)
                        num_crash_syscall += 1
                        crash_arr_syscall.append(crash)
                        crashed_call = code2Syscall.parse_syscall(item.call_trace)
                        print('Crashed Syscall:', crashed_call)
                        if len(crashed_call) == 1:
                            print('Single Crashed Syscall!!!')
                        break

            for item in crash.crash_items:
                if item.call_trace is not None:
                    if item.if_call_trace_from_forked():
                        found_item = item
                        print('Found background thread related call trace', item.report_link)
                        num_crash_backthread += 1
                        break

            for item in crash.crash_items:
                if item.call_trace is not None:
                    if item.if_call_trace_from_exited():
                        found_item = item
                        print('Found exiting system mode related call trace', item.report_link)
                        num_crash_exiting += 1
                        break

            for item in crash.crash_items:
                if item.call_trace is not None:
                    if item.if_call_trace_from_interrupt():
                        found_item = item
                        print('Found interrupt related call trace', item.report_link)
                        num_crash_interrupt += 1
                        break

            if found_report:
                num_tot_crash += 1
            else:
                print('Cannot find call trace, please manually check', crash.link)

            if not found_item:
                print('Cannot determine type, please manually check', crash.link)
            print()

        print('Crash Call Trace Related to System Call: {}/{}/{}'.format(num_crash_syscall, num_tot_crash,
                                                                         len(crash_arr)))
        print('Crash Call Trace Related to Background Thread: {}/{}/{}'.format(num_crash_backthread, num_tot_crash,
                                                                               len(crash_arr)))
        print('Crash Call Trace Related to Exiting To User Mode: {}/{}/{}'.format(num_crash_exiting, num_tot_crash,
                                                                                  len(crash_arr)))
        print('Crash Call Trace Related to Interrupt: {}/{}/{}'.format(num_crash_interrupt, num_tot_crash,
                                                                       len(crash_arr)))
        print('Len of Crash Arr Syscall: ', len(crash_arr_syscall))
        print()

        # num_stateful = 0
        # for idx, crash in enumerate(crash_arr_syscall):
        #     if not crash.guess_if_not_stateful():
        #         num_stateful += 1
        #         print('Processing {}/{}:'.format(idx, len(crash_arr_syscall)), crash.title)
        #         print('Crash is stateful, can fall into our problem, num:', num_stateful, crash.link)
        #     else:
        #         print('Processing {}/{}:'.format(idx, len(crash_arr_syscall)), crash.title)
        #         print('Crash is not stateful, omit', crash.link)
        #     print()
            # json_data = json.dumps(crash_arr, cls=MyEncoder, indent=4)
            # with open("fixed_crash.json", "w") as file:
            #     file.write(json_data)