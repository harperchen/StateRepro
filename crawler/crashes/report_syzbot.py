from __future__ import annotations

import time
from bs4 import BeautifulSoup
from datetime import datetime
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from crashes.report_local import *


class ReportRemote(KernelReport):
    def __init__(self, time=None, kernel_commit=None,
                 raw_console_log=None, console_log_link=None,
                 raw_report=None, report_link=None,
                 syz_repro=None, syz_repro_link=None,
                 call_trace=None, syscall_names=None,
                 crash_syscalls=[], calibrate_crash_syscalls=[]):
        KernelReport.__init__(kernel_commit, raw_console_log, raw_report, syz_repro, call_trace, crash_syscalls)
        self.time: str = time
        self.console_log_link: str = console_log_link
        self.report_link: str = report_link
        self.syz_repro_link: str = syz_repro_link
        self.syscall_names: str = syscall_names
        self.calibrate_crash_syscalls: List[str] = calibrate_crash_syscalls

    def retrieve_report_remote(self, report_link: str):
        """
        parse crash report from url
        """
        if report_link == '':
            return

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
        self.raw_report = report_data
        self.retrieve_call_trace()

    def retrieve_console_log_remote(self, console_log_link: str):
        """
        parse all syz programs recorded in execution log
        """
        if console_log_link == '':
            return

        time.sleep(1)
        session = requests.Session()
        retry = Retry(connect=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        response = session.get(self.console_log_link)
        self.raw_console_log = response.text
        self.retrieve_executed_seqs()

    def retrieve_repro_remote(self, syz_repro_link):
        """
        parse the reproducer for the crash if exists
        """
        if syz_repro_link == '':
            return

        time.sleep(1)
        session = requests.Session()
        retry = Retry(connect=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        response = session.get(syz_repro_link)
        self.raw_repro = response.text
        self.syz_repro_link = syz_repro_link

        if self.raw_repro is not None:
            self.short_repro = parse_sysprog(self.raw_repro)


class CrashRemote:
    def __init__(self, title=None, crash_link=None, report_items: List[ReportRemote] = [], subsystem=None,
                 poc_interval=None):
        self.crash_link = crash_link
        if '\n' in title:
            self.title: str = title.split('\n')[0]
            self.subsystem: str = '_'.join(title.split('\n')[1:])
        else:
            self.title: str = title
            self.subsystem: str = subsystem
        self.report_items: List[ReportRemote] = report_items
        self.poc_interval = poc_interval

    def add_crash(self, new_crash):
        self.report_items.append(new_crash)

    def get_first_repro_time(self):
        """
        compute the time interval from first time the crash occur and the time when a reproducer is available
        """
        time_format = "%Y/%m/%d %H:%M"
        time_slots = [datetime.strptime(item.time, time_format) for item in self.report_items]
        earliest_time_slot = min(time_slots)
        non_none_time_slots = []
        for item in self.report_items:
            if item.syz_repro is not None:
                non_none_time_slots.append(datetime.strptime(item.time, time_format))
        if len(non_none_time_slots) != 0:
            non_none_earliest_time_slot = min(non_none_time_slots)
            time_interval = non_none_earliest_time_slot - earliest_time_slot
        else:
            time_interval = None
        self.poc_interval = time_interval

    def retrieve_all_crashes(self):
        time.sleep(1)
        response = requests.get(self.crash_link)
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
                kernel_commit = cells[commit_index].get_text().strip()
                cur_item = ReportRemote(item_time, kernel_commit)

                if cells[report_index].find('a') is not None:
                    report_link = "https://syzkaller.appspot.com" + cells[report_index].find('a')['href']
                    cur_item.retrieve_report_remote(report_link)

                console_name = cells[console_index].get_text().strip()
                if console_name != 'strace log':
                    cur_item.console_link = "https://syzkaller.appspot.com" + cells[console_index].find('a')['href']
                    cur_item.console_data = ''

                if cells[syz_repro_index].find('a') is not None:
                    syz_repro_link = "https://syzkaller.appspot.com" + cells[syz_repro_index].find('a')['href']
                    cur_item.retrieve_repro_remote(syz_repro_link)

                self.add_crash(cur_item)
        self.get_first_repro_time()


def parse_syzbot_tables(bug_status: str) -> List[CrashRemote]:
    crash_array: List[CrashRemote] = []
    url = 'https://syzkaller.appspot.com/upstream/' + bug_status
    response = requests.get(url)

    soup = BeautifulSoup(response.content, 'html.parser')
    table = soup.find('table', class_='list_table')

    headers = table.find_all('th')
    repro_index = [i for i, header in enumerate(headers) if header.get_text().strip() == 'Repro'][0]

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
                    crash = CrashRemote(title, "https://syzkaller.appspot.com" + link)
                    crash_array.append(crash)
    print('Total Fixed Crashes: ', len(rows))
    print('Total Crashes with Repro: ', num_with_repro)
    print('Total Crashes with Repro but Not Data Race: ', len(crash_array))
    return crash_array


class CrashListEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ReportRemote):
            return obj.__dict__  # Convert MyClass object to a dictionary
        elif isinstance(obj, CrashRemote):
            return {
                **obj.__dict__,  # Convert Address object to a dictionary
                "poc_interval": str(obj.poc_interval)
            }
        return super().default(obj)


class CrashListDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.custom_object_hook, *args, **kwargs)

    def custom_object_hook(self, obj) -> CrashRemote:
        if 'link' in obj and 'title' in obj and 'subsystem' in obj and 'poc_interval' in obj and 'report_items' in obj:
            report_items = []
            poc_interval = None
            if obj['poc_interval'] != 'None':
                poc_interval = pd.Timedelta(obj['poc_interval'])
            for report in obj['report_items']:
                syscall_names = report.get('syscall_names', [])
                crash_syscalls = report.get('crash_syscalls', [])
                calibrate_crash_syscalls = report.get('calibrate_crash_syscalls', [])
                report_items.append(ReportRemote(report['time'],
                                                 report['commit'],
                                                 report['console_log'],
                                                 report['console_log_link'],
                                                 report['report'],
                                                 report['report_link'],
                                                 report['syz_repro'],
                                                 report['syz_repro_link'],
                                                 report['call_trace'],
                                                 syscall_names,
                                                 crash_syscalls,
                                                 calibrate_crash_syscalls))
            return CrashRemote(obj['title'], obj['link'], report_items, obj['subsystem'], poc_interval)
        return obj


class MyDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.custom_object_hook, *args, **kwargs)

    def custom_object_hook(self, obj) -> CrashRemote:
        if 'link' in obj and 'title' in obj and 'subsystem' in obj and 'poc_interval' in obj and 'crash_items' in obj:
            report_items = []
            poc_interval = None
            if obj['poc_interval'] != 'None':
                poc_interval = pd.Timedelta(obj['poc_interval'])
            for report in obj['crash_items']:
                syscall_names = report.get('syscall_names', [])
                report_items.append(ReportRemote(report['time'],
                                                 report['commit'],
                                                 report['console_log'],
                                                 report['console_log_link'],
                                                 report['report'],
                                                 report['report_link'],
                                                 report['syz_repro'],
                                                 report['syz_repro_link'],
                                                 report['call_trace'],
                                                 syscall_names))
            return CrashRemote(obj['title'], obj['link'], report_items, obj['subsystem'], poc_interval)
        return obj


if __name__ == '__main__':
    # parse a specific crash
    crash = CrashRemote(crash_link='https://syzkaller.appspot.com/bug?extid=e3f8d4df1e1981a97abb')
    crash.retrieve_all_crashes()
