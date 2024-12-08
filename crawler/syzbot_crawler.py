import os.path
import sys
import time
import requests

from syscall_resolver import *
from dump_resolver import *
from poc_resolver import *

from typing import List
from bs4 import BeautifulSoup
from datetime import datetime
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

dump_resolver = DumpResolver()
syscall_resolver = SyscallResolver()
poc_resolver = PoCResolver()

class CrashCrawler:
    def __init__(self, time=None, commit=None,
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

    @staticmethod
    def parse_crash(crash_link: str):
        time.sleep(1)
        response = requests.get(crash_link)
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
                cur_item = CrashCrawler(item_time, commit)

                cur_item.parse_report(cells[report_index])
                cur_item.parse_console_log(cells[console_index])
                cur_item.parse_syz_repro(cells[syz_repro_index])

                crash.add_crash(cur_item)
        crash.get_first_repro_time()


class ReportInfo:
    def __init__(self, title, link, crash_items: List[CrashCrawler], subsystem='', poc_interval=None):
        self.link = link
        if '\n' in title:
            self.title = title.split('\n')[0]
            self.subsystem = '_'.join(title.split('\n')[1:])
        else:
            self.title = title
            self.subsystem = subsystem
        self.crash_items: List[CrashCrawler] = crash_items
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
    def parse_table(bug_status: str):
        crash_array: List[ReportInfo] = []
        url = 'https://syzkaller.appspot.com/upstream/' + bug_status
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
                        crash = ReportInfo(title, "https://syzkaller.appspot.com" + link)
                        crash_array.append(crash)
        print('Total Fixed Crashes: ', len(rows))
        print('Total Crashes with Repro: ', num_with_repro)
        print('Total Crashes with Repro but Not Data Race: ', len(crash_array))
        return crash_array


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, CrashCrawler):
            return obj.__dict__  # Convert MyClass object to a dictionary
        elif isinstance(obj, ReportInfo):
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
                crash_items.append(CrashCrawler(commit['time'],
                                                commit['commit'],
                                                commit['console_log'],
                                                commit['console_log_link'],
                                                commit['report'],
                                                commit['report_link'],
                                                commit['syz_repro'],
                                                commit['syz_repro_link'],
                                                commit['call_trace'],
                                                syscall_names))
            return ReportInfo(obj['title'], obj['link'], crash_items, obj['subsystem'], poc_interval)
        return obj


if __name__ == '__main__':

    if sys.argv[1] == 'case':
        # parse a specific crash
        CrashCrawler.parse_crash('https://syzkaller.appspot.com/bug?id=5270676317f74d30265abb76b7ca58b5608ca545')

    elif sys.argv[1] == 'crawl':
        # crawl information of all fixed crashes yet with available reproducer
        if os.path.exists('fixed_crash.json'):
            with open('fixed_crash.json', 'r') as f:
                crash_array = json.loads(f.read(), cls=MyDecoder)
        else:
            crash_array = ReportInfo.parse_table("fixed")

        # parse the link of each crash
        for idx, crash in enumerate(crash_array):
            print("Processing {}/{}: {} {}".format(idx, len(crash_array), crash.title, crash.link))
            if crash.poc_interval is None:
                time.sleep(1)
                CrashCrawler.parse_crash(crash.link)
                json_data = json.dumps(crash_array, cls=MyEncoder, indent=4)
                with open("fixed_crash.json", "w") as file:
                    file.write(json_data)

    elif sys.argv[1] == 'analyze':
        with open('fixed_crash.json', 'r') as f:
            crash_array = json.loads(f.read(), cls=MyDecoder)

        num_crash_syscall = 0
        num_crash_interrupt = 0
        num_crash_backthread = 0
        num_crash_exiting = 0
        num_tot_crash = 0

        for idx, crash in enumerate(crash_array):
            # parse call trace
            print('Processing {}/{}: {}, {}'.format(idx, len(crash_array), crash.title, crash.link))
            print('Crash times: ', len(crash.crash_items))

            found_report = False
            for item in crash.crash_items:
                if item.report is None:
                    continue
                item.call_trace = dump_resolver.parse_call_trace(item.report)
                if item.syz_repro is None:
                    continue
                item.syscall_names = poc_resolver.parse_sysprog(item.syz_repro)
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
                    print()
                    print('Found syscall related call trace', item.report_link)
                    num_crash_syscall += 1
                    crashed_calls = syscall_resolver.parse_syscall_from_trace(item.call_trace)
                    calibrated_calls = poc_resolver.calibrate_crashed_call_from_poc(item.syscall_names, crashed_calls)
                    print(item.call_trace)
                    print('Crashed Syscall:', crashed_calls)
                    print('Calibrated Syscall: ', calibrated_calls)

                    if len(crashed_calls) == 1:
                        print('Single Crashed Syscall!!!')
                    if len(calibrated_calls) == 1:
                        print('Correct Infer Syscall!!!')
                    break

                else:
                    print('Unknown call trace', item.report_link)
                    print(item.call_trace)
                    break

            for item in crash.crash_items:
                if item.syscall_names is None:
                    continue
                print('PoC: ', item.syscall_names)

            if found_report:
                num_tot_crash += 1
            else:
                print('Cannot find call trace, please manually check', crash.link)

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
