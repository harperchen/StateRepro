from __future__ import annotations

import time
import requests

from syscall_resolver import *
from dump_resolver import *

from typing import List
from bs4 import BeautifulSoup
from datetime import datetime
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter


class ReportCrawler:
    def __init__(self, time=None, commit=None,
                 console_log=None, console_log_link=None,
                 report=None, report_link=None,
                 syz_repro=None, syz_repro_link=None,
                 call_trace=None, syscall_names=None):
        self.time: str = time
        self.commit: str = commit

        self.console_log: str = console_log
        self.console_log_link: str = console_log_link

        self.report: str = report
        self.report_link: str = report_link

        self.syz_repro: str = syz_repro
        self.syz_repro_link: str = syz_repro_link

        self.call_trace: str = call_trace
        self.syscall_names: str = syscall_names

        self.crash_syscalls: List[str] = []
        self.calibrate_crash_syscalls: List[str] = []

    def parse_dump(self, report_cell):
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
            console_data = ''

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

        all_executed_progs = []
        for segment in segments:
            syz_prog = '\n'.join(segment.split('\n')[1:-2])
            all_executed_progs.append(syz_prog)

        self.console_log = '\n\n'.join(all_executed_progs)

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



class CrashCrawler:
    def __init__(self, title, link, report_items: List[ReportCrawler], subsystem='', poc_interval=None):
        self.link = link
        if '\n' in title:
            self.title: str = title.split('\n')[0]
            self.subsystem: str = '_'.join(title.split('\n')[1:])
        else:
            self.title: str = title
            self.subsystem: str = subsystem
        self.report_items: List[ReportCrawler] = report_items
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

    @staticmethod
    def parse_syzbot_tables(bug_status: str) -> List[CrashCrawler]:
        crash_array: List[CrashCrawler] = []
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
                        crash = CrashCrawler(title, "https://syzkaller.appspot.com" + link)
                        crash_array.append(crash)
        print('Total Fixed Crashes: ', len(rows))
        print('Total Crashes with Repro: ', num_with_repro)
        print('Total Crashes with Repro but Not Data Race: ', len(crash_array))
        return crash_array

    @staticmethod
    def parse_crash(crash_link: str):
        time.sleep(1)
        crash = CrashCrawler(title=crash_link)
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
                cur_item = ReportCrawler(item_time, commit)

                cur_item.parse_dump(cells[report_index])
                cur_item.parse_console_log(cells[console_index])
                cur_item.parse_syz_repro(cells[syz_repro_index])

                crash.add_crash(cur_item)
        crash.get_first_repro_time()


class CrashListEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ReportCrawler):
            return obj.__dict__  # Convert MyClass object to a dictionary
        elif isinstance(obj, CrashCrawler):
            return {
                **obj.__dict__,  # Convert Address object to a dictionary
                "poc_interval": str(obj.poc_interval)
            }
        return super().default(obj)


class CrashListDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.custom_object_hook, *args, **kwargs)

    def custom_object_hook(self, obj) -> CrashCrawler:
        if 'link' in obj and 'title' in obj and 'subsystem' in obj and 'poc_interval' in obj and 'report_items' in obj:
            report_items = []
            poc_interval = None
            if obj['poc_interval'] != 'None':
                poc_interval = pd.Timedelta(obj['poc_interval'])
            for report in obj['report_items']:
                syscall_names = report.get('syscall_names', [])
                report_items.append(ReportCrawler(report['time'],
                                                  report['commit'],
                                                  report['console_log'],
                                                  report['console_log_link'],
                                                  report['report'],
                                                  report['report_link'],
                                                  report['syz_repro'],
                                                  report['syz_repro_link'],
                                                  report['call_trace'],
                                                  syscall_names))
            return CrashCrawler(obj['title'], obj['link'], report_items, obj['subsystem'], poc_interval)
        return obj

class MyDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.custom_object_hook, *args, **kwargs)

    def custom_object_hook(self, obj) -> CrashCrawler:
        if 'link' in obj and 'title' in obj and 'subsystem' in obj and 'poc_interval' in obj and 'crash_items' in obj:
            report_items = []
            poc_interval = None
            if obj['poc_interval'] != 'None':
                poc_interval = pd.Timedelta(obj['poc_interval'])
            for report in obj['crash_items']:
                syscall_names = report.get('syscall_names', [])
                report_items.append(ReportCrawler(report['time'],
                                                  report['commit'],
                                                  report['console_log'],
                                                  report['console_log_link'],
                                                  report['report'],
                                                  report['report_link'],
                                                  report['syz_repro'],
                                                  report['syz_repro_link'],
                                                  report['call_trace'],
                                                  syscall_names))
            return CrashCrawler(obj['title'], obj['link'], report_items, obj['subsystem'], poc_interval)
        return obj
    
if __name__ == '__main__':
    # parse a specific crash
    CrashCrawler.parse_crash('https://syzkaller.appspot.com/bug?id=5270676317f74d30265abb76b7ca58b5608ca545')
