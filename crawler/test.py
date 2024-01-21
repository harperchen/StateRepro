import re
import time
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter


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

if __name__ == '__main__':
    time.sleep(1)
    # response = requests.get(self.console_log_link, headers=headers_429)session = requests.Session()
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    response = session.get("https://syzkaller.appspot.com/text?tag=CrashLog&x=17b34d06a80000")
    console_data = response.text

    # extract executed programs
    pattern = "\d{2}:\d{2}:\d{2} executing program \d+:\n"
    p = re.compile(pattern)
    m = p.search(console_data)
    if m:
        segments = re.findall(pattern, console_data)
        segments = [segment + console_data.split(segment, 1)[1].split('\n\n', 1)[0] + '\n\n' for segment in segments]
        all_progs = []
        for segment in segments:
            syz_prog = '\n'.join(segment.split('\n')[1:-2])
            syscalls = parse_sysprog(syz_prog)
            all_progs.append(syscalls)

    print('\n'.join(all_progs))