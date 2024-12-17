import re, sys, os, stat
import requests
from typing import List
from subprocess import call, Popen, PIPE, STDOUT
import logging
import random
import json
from time import sleep
import datetime

FILE_HANDLER = 0
STREAM_HANDLER = 1

def parse_sysprog(syz_prog: str) -> str:
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


def is_sub_array(array1: List[str], array2: List[str]):
    i = 0  # Pointer for array1
    j = 0  # Pointer for array2

    while i < len(array1) and j < len(array2):
        if array1[i].startswith(array2[j]):
            i += 1
        j += 1

    return i == len(array1)  # Return True if all elements of array1 were found in array2


def regx_match(regx, line) -> bool:
    m = re.search(regx, line)
    if m is not None and len(m.group()) != 0:
        return True
    return False


def regx_get(regx, line, index):
    m = re.search(regx, line)
    if m is not None and len(m.groups()) > index:
        return m.groups()[index]
    return None


def local_command(command, cwd=None, shell=False, redir_err=False, logger=None):
    out = []
    if redir_err:
        p = Popen(args=command, shell=shell, cwd=cwd, stdout=PIPE, stderr=PIPE)
    else:
        p = Popen(args=command, shell=shell, cwd=cwd, stdout=PIPE, stderr=STDOUT)
    with p.stdout:
        try:
            for line in iter(p.stdout.readline, b''):
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    continue
                if logger != None:
                    logger.info(line)
                out.append(line)
                #if debug:
                #print(line)
        except ValueError:
            if p.stdout.close:
                return out
    return out


def init_logger(logger_id, cus_format='%(asctime)s %(message)s', debug=False, propagate=False,
                handler_type=FILE_HANDLER):
    ran = random.getrandbits(8)
    if (handler_type == FILE_HANDLER):
        handler = logging.FileHandler(logger_id)
        format = logging.Formatter(cus_format)
        handler.setFormatter(format)
    if (handler_type == STREAM_HANDLER):
        handler = logging.StreamHandler(sys.stdout)
        format = logging.Formatter(cus_format)
        handler.setFormatter(format)
    logger = logging.getLogger(logger_id)
    for each_handler in logger.handlers:
        logger.removeHandler(each_handler)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = propagate
    if debug:
        logger.setLevel(logging.DEBUG)
    return logger



def set_timer(timeout, p):
    count = 0
    while (count != timeout):
        count += 1
        sleep(1)
        if p.poll() != None:
            return
    if p.poll() is None:
        p.kill()
    return


def syzrepro_convert_format(line):
    res = {}
    p = re.compile(r'({| )(\w+):([0-9a-zA-Z-]*)')
    raw = p.sub(r'\1"\2":"\3",', line)
    if raw[raw.find('}') - 1] == ',':
        new_line = raw[:raw.find('}') - 1] + "}"
    else:
        new_line = raw
    if 'LegacyOptions' in new_line:
        idx = new_line.index('LegacyOptions') - 3
        new_line = new_line[:idx] + "}"
    pm = json.loads(new_line)
    for each in pm:
        if each == 'Threaded':
            res['threaded'] = pm[each]
        if each == 'Collide':
            res['collide'] = pm[each]
        if each == 'Repeat':
            res['repeat'] = pm[each]
        if each == 'Procs':
            res['procs'] = pm[each]
        if each == 'Sandbox':
            res['sandbox'] = pm[each]
        if each == 'FaultCall':
            res['fault_call'] = pm[each]
        if each == 'FaultNth':
            res['fault_nth'] = pm[each]
        if each == 'EnableTun' or each == 'NetInjection':
            res['tun'] = pm[each]
        if each == 'EnableCgroups' or each == 'Cgroups':
            res['cgroups'] = pm[each]
        if each == 'UseTmpDir':
            res['tmpdir'] = pm[each]
        if each == 'HandleSegv':
            res['segv'] = pm[each]
        if each == 'Fault':
            res['fault'] = pm[each]
        if each == 'WaitRepeat':
            res['wait_repeat'] = pm[each]
        if each == 'Debug':
            res['debug'] = pm[each]
        if each == 'Repro':
            res['repro'] = pm[each]
        if each == 'NetDevices':
            res['netdev'] = pm[each]
        if each == 'NetReset':
            res['resetnet'] = pm[each]
        if each == 'BinfmtMisc':
            res['binfmt_misc'] = pm[each]
        if each == 'CloseFDs':
            res['close_fds'] = pm[each]
        if each == 'DevlinkPCI':
            res['devlinkpci'] = pm[each]
        if each == 'USB':
            res['usb'] = pm[each]
    #if len(pm) != len(res):
    #    self.logger.info("parameter is missing:\n%s\n%s", new_line, str(res))
    return res



def chmodX(path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)

def log_anything(pipe, logger, debug):
    try:
        for line in iter(pipe.readline, b''):
            try:
                line = line.decode("utf-8").strip('\n').strip('\r')
            except:
                logger.info('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                continue
            logger.info(line)
            if debug:
                print(line)
    except ValueError:
        if pipe.close:
            return

def request_get(url):
    '''
    Try request a url for 5 times with Chrome's User-Agent
    '''
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'}
    failed = 0
    while failed < 5:
        r = requests.request(method='GET', url=url, headers=headers)
        if r.status_code == 200:
            #print(f'[+]Success on crawl {url}')
            return r
        failed += 1
        #print(f'[*]Failed on crawl {url} for {failed} times')
        sleep(5)
    #Ok... let's just return
    return requests.request(method='GET', url=url, headers=headers)



def set_compiler_version(time, config_url):
    GCC = 0
    CLANG = 1
    regx_gcc_version = r'gcc \(GCC\) (\d+).\d+.\d+ (\d+)'
    regx_clang_version = r'clang version (\d+).\d+.\d+ \(https:\/\/github\.com\/llvm\/llvm-project\/ (\w+)\)'
    compiler = -1
    ret = ""

    r = request_get(config_url)
    text = r.text.split('\n')
    for line in text:
        if line.find('Compiler:') != -1:
            if regx_match(regx_gcc_version, line):
                compiler = GCC
                version = regx_get(regx_gcc_version, line, 0)
                commit = regx_get(regx_gcc_version, line, 1)
            if regx_match(regx_clang_version, line):
                compiler = CLANG
                version = regx_get(regx_clang_version, line, 0)
                commit = regx_get(regx_clang_version, line, 1)
            break
        if line.find('CONFIG_CC_VERSION_TEXT') != -1:
            if regx_match(regx_gcc_version, line):
                compiler = GCC
                version = regx_get(regx_gcc_version, line, 0)
                commit = regx_get(regx_gcc_version, line, 1)
            if regx_match(regx_clang_version, line):
                compiler = CLANG
                version = regx_get(regx_clang_version, line, 0)
                commit = regx_get(regx_clang_version, line, 1)
            break

    if compiler == GCC:
        if version == '7':
            ret = "gcc-7"
        if version == '8':
            ret = "gcc-8.0.1-20180412"
        if version == '9':
            ret = "gcc-9.0.0-20181231"
        if version == '10':
            ret = "gcc-10.1.0-20200507"

    if compiler == CLANG:
        if version == '7' and version.find('329060'):
            ret = "clang-7-329060"
        if version == '7' and version.find('334104'):
            ret = "clang-7-334104"
        if version == '8':
            ret = "clang-8-343298"
        if version == '10':
            #clang-10-c2443155 seems corrput (Compiler lacks asm-goto support)
            #return clang-11-ca2dcbd030e
            ret = "clang-11-ca2dcbd030e"
        if version == '11':
            ret = "clang-11-ca2dcbd030e"

    if compiler == -1:
        #filter by timestamp
        t1 = datetime.datetime(2018, 3, 1)
        t2 = datetime.datetime(2018, 4, 12)
        t3 = datetime.datetime(2018, 12, 31)
        t4 = datetime.datetime(2020, 5, 7)

        if time < t1:
            ret = "gcc-7"
        if time >= t1 and time < t2:
            #gcc-8.0.1-20180301 seems corrput (Compiler lacks asm-goto support)
            #return "gcc-8.0.1-20180301"
            ret = "gcc-8.0.1-20180412"
        if time >= t2 and time < t3:
            ret = "gcc-8.0.1-20180412"
        if time >= t3 and time < t4:
            ret = "gcc-9.0.0-20181231"
        if time >= t4:
            ret = "gcc-10.1.0-20200507"
    return ret

