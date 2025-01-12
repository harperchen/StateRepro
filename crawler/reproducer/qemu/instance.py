import threading
import socket
import traceback
import time
import os, queue

from time import sleep
from subprocess import Popen, PIPE, STDOUT, call
from .connect import VMConnect
from utils import *

reboot_regx = r'reboot: machine restart'
port_error_regx = r'Could not set up host forwarding rule'
default_output_timer = 5


class VMInstance(VMConnect):
    UPSTREAM = 1

    def __init__(self, hash_tag, tag='', work_path='/tmp/', log_name='vm.log', log_suffix="", debug=False):
        self.work_path = work_path
        self.port = None
        self.image = None
        self.cmd_launch = None
        self.timeout = None
        self.logger = None
        self.debug = debug
        self.logger = None
        self.tag = hash_tag
        self.hash_tag = hash_tag
        self.log_name = log_name
        self.alternative_func = None
        self.alternative_func_args = None
        self.alternative_func_output = None
        self.alternative_func_finished = False
        self._qemu_return = queue.Queue()
        self.qemu_ready = False
        self.kill_qemu = False
        self.trigger_crash = False
        self._shutdown = False
        self.qemu_fail = False
        self.dumped_ftrace = False
        self.output = []
        self._output_timer = default_output_timer
        self._output_lock = None
        self._reboot_once = False
        self.lock = None
        log_name += log_suffix
        self.logger = init_logger(log_name, debug=debug, propagate=debug)
        self.timer = 0
        if tag != '':
            self.tag = tag
        self.instance = None
        self._killed = False
        VMConnect.__init__(self, self.logger, self.debug, self.debug)

    def log_thread(func):
        def inner(self, *args):
            self.logger.info("Start thread: {}".format(func.__name__))
            ret = func(self, *args)
            self.logger.info("Exit thread: {}".format(func.__name__))
            return ret

        return inner

    def reset(self):
        self.qemu_ready = False
        self.kill_qemu = False
        self.trigger_crash = False
        self._killed = False
        self.qemu_fail = False
        self.dumped_ftrace = False
        # self.qemu_ready_bar = ""
        self.output = []
        self._output_timer = default_output_timer
        self._output_lock = threading.Lock()
        self._reboot_once = False
        self.lock = threading.Lock()
        self.alternative_func_finished = False

    def run(self, alternative_func=None, alternative_func_output=None, args=()):
        """
        alternative_func: function to be called when qemu is ready
        args: arguments to be passed to alternative_func

        return:
            p: process of qemu
            queue: queue of alternative_func's custom output
        """
        self.reset()
        p = Popen(self.cmd_launch, stdout=PIPE, stderr=STDOUT)
        self.instance = p

        self.alternative_func = alternative_func
        self.alternative_func_args = args
        self.alternative_func_output = alternative_func_output

        if self.alternative_func is not None and alternative_func_output is None:
            self.alternative_func_output = queue.Queue()

        x = threading.Thread(target=self.monitor_execution, name="{} qemu killer".format(self.tag))
        x.start()
        x1 = threading.Thread(target=self.__log_qemu, args=(p.stdout,), name="{} qemu logger".format(self.tag),
                              daemon=True)
        x2 = threading.Thread(target=self._new_output_timer, name="{} qemu output timer".format(self.tag), daemon=True)
        x1.start()
        x2.start()

        return p, self.alternative_func_output

    def send(self, data):
        self.alternative_func_output.put(data)

    def _send_return_value(self, ret):
        self._qemu_return.put(ret)

    def recv(self, block=False, timeout=None):
        return self.alternative_func_output.get(block=block, timeout=timeout)

    def recvall(self):
        res = []
        while True:
            try:
                r = self.alternative_func_output.get(block=False)
                res.append(r)
            except queue.Empty:
                break
        return res

    def wait(self):
        ret = self._qemu_return.get(block=True)
        return ret

    def shutdown(self):
        self._shutdown = True
        self.command(user='root', cmds="shutdown -h now", wait=False)

    def kill_vm(self):
        self.logger.info('Kill VM pid: {}'.format(self.instance.pid))
        if self._killed:
            return
        self._killed = True
        try:
            if self._shutdown:
                n = 30
                while n > 0:
                    if self.instance.poll() is None:
                        time.sleep(1)
                        n -= 1
                    else:
                        break
            self.instance.kill()
            time.sleep(3)
        except:
            self.logger.error("VM exit abnormally")
        if self._output_lock.locked():
            self._output_lock.release()
        if self.lock.locked():
            self.lock.release()

    def write_cmd_to_script(self, cmd, name, build_append=False):
        path_name = os.path.join(self.work_path, name)
        with open(path_name, "w") as f:
            if build_append:
                f.write(" ".join(cmd[:-1]))
                f.write(" \"" + cmd[-1:][0] + "\"")
            else:
                f.write(" ".join(cmd))
            f.close()

    def upload(self, user, src: list, dst, wait: bool):
        if type(src) != list:
            self.logger.error("src must be a list")
        ret = self.scp("localhost", user, self.port, self.key, src, dst, True, wait)
        return ret

    def download(self, user, src: list, dst, wait: bool):
        if type(src) != list:
            self.logger.error("src must be a list")
        ret = self.scp("localhost", user, self.port, self.key, src, dst, False, wait)
        return ret

    # If wait is True, return the output of the command
    # If wait is False, return the thread instance
    def command(self, cmds, user, wait: bool, timeout=None):
        ret = self.ssh("localhost", user, self.port, self.key, cmds, wait, timeout)
        return ret

    @log_thread
    def monitor_execution(self):
        booting_timer = 0
        self.timer = 0
        run_alternative_func = False
        error_count = 0
        while not self.func_finished() and (self.timeout is None or self.timer < self.timeout) and booting_timer < 180:
            if self.kill_qemu:
                self.logger.info('Signal kill qemu received.')
                if not self.qemu_ready:
                    self._send_return_value(False)
                self.kill_vm()
                return
            self.timer += 1
            if not self.qemu_ready:
                booting_timer += 1
            time.sleep(1)
            poll = self.instance.poll()
            if poll is not None:
                if not self.qemu_ready:
                    self.kill_proc_by_port(self.port)
                    self.logger.error('QEMU: Error occur at booting qemu')
                    if self.need_reboot():
                        if self._reboot_once:
                            self.logger.debug('QEMU: Image reboot already')
                            # The image should be ready after rebooting, run instance again
                            self._enable_snapshot_in_cmd()
                            self.run(self.alternative_func, self.alternative_func_output, self.alternative_func_args)
                            return
                        self._reboot_once = True
                        self.logger.error('QEMU: Upstream image need a reboot')
                        break
                    self.qemu_fail = True
                if self._output_lock.locked():
                    self._output_lock.release()
                if not self.func_finished():
                    self._send_return_value(False)
                self.kill_vm()
                return
            if not self.qemu_ready and self.is_qemu_ready():
                self.qemu_ready = True
                self.timer = 0
                time.sleep(10)
                if self.alternative_func is not None and not run_alternative_func:
                    x = threading.Thread(target=self._prepare_alternative_func,
                                         name="{} qemu call back".format(self.tag))
                    x.start()
                    run_alternative_func = True
        if run_alternative_func:
            self.logger.info('Finished alternative function, kill qemu')
        if self._reboot_once and not run_alternative_func:
            self.logger.debug('QEMU: Try to reboot the image')
            # Disable snapshot and reboot the image
            self._disable_snapshot_in_cmd()
            self.kill_vm()
            self.run(self.alternative_func, self.alternative_func_output, self.alternative_func_args)
            return
        if not self.qemu_ready:
            self.qemu_fail = True
        if self.qemu_fail:
            self._send_return_value(False)
        self.kill_vm()
        return

    def func_finished(self):
        return self.alternative_func_finished

    def kill_proc_by_port(self, ssh_port):
        p = Popen("lsof -i :{} | awk '{{print $2}}'".format(ssh_port), shell=True, stdout=PIPE, stderr=PIPE)
        is_pid = False
        pid = -1
        with p.stdout as pipe:
            for line in iter(pipe.readline, b''):
                line = line.strip().decode('utf-8')
                if line == 'PID':
                    is_pid = True
                    continue
                if is_pid:
                    pid = int(line)
                    call("kill -9 {}".format(pid), shell=True)
                    break

    # No new output in (default_output_timer) seconds
    def no_new_output(self):
        return self._output_lock.locked()

    def need_reboot(self):
        if self.kernel.type != VMInstance.UPSTREAM:
            return False
        if len(self.output) == 0:
            return False
        return 'reboot: machine restart' in self.output[-1]

    def is_qemu_ready(self):
        output = self.command("uname -r", "root", wait=True, timeout=5)
        if output is None:
            self.logger.warn("QEMU: SSH does not respond")
            return False
        if type(output) == list and len(output) > 0:
            for line in output:
                if regx_match(r'^\d+\.\d+', line):
                    return True
        else:
            return False
        return False

    def prepare_qemu_launch_cmd(self, kernel, port, image, mem="4G", cpu="2", key=None, gdb_port=-1, mon_port=-1, opts=None,
                                timeout=None, kasan_multi_shot=0, snapshot=True):
        # self.qemu_ready_bar = r'Debian GNU\/Linux \d+ syzkaller ttyS\d+'
        self.kernel = kernel
        cur_opts = ["root=/dev/sda", "console=ttyS0"]
        def_opts = ["earlyprintk=serial",
                    "ftrace_dump_on_oops", "rodata=n", "vsyscall=native", "net.ifnames=0",
                    "biosdevname=0", "kvm-intel.nested=1",
                    "kvm-intel.unrestricted_guest=1", "kvm-intel.vmm_exclusive=1",
                    "kvm-intel.fasteoi=1", "kvm-intel.ept=1", "kvm-intel.flexpriority=1",
                    "kvm-intel.vpid=1", "kvm-intel.emulate_invalid_guest_state=1",
                    "kvm-intel.eptad=1", "kvm-intel.enable_shadow_vmcs=1", "kvm-intel.pml=1",
                    "kvm-intel.enable_apicv=1", "panic_on_warn=0", "kasan_multi_shot=1"]
        self.port = port
        self.image = image
        self.key = key
        self.timeout = timeout
        self.cmd_launch = ["qemu-system-x86_64", "-m", mem, "-smp", cpu]
        if gdb_port != -1:
            self.cmd_launch.extend(["-gdb", "tcp::{}".format(gdb_port)])
        if mon_port != -1:
            self.cmd_launch.extend(["-monitor", "tcp::{},server,nowait,nodelay".format(mon_port)])
        if self.port is not None:
            self.cmd_launch.extend(
                ["-net", "nic,model=e1000", "-net", "user,host=10.0.2.10,hostfwd=tcp::{}-:22".format(self.port)])
        self.cmd_launch.extend(
            ["-display", "none", "-serial", "stdio", "-no-reboot", "-enable-kvm", "-cpu", "host,migratable=off",
             "-hda", "{}".format(self.image)])
        if snapshot:
            self.cmd_launch.append("-snapshot")

        self.cmd_launch.extend(["-kernel", "/home/weichen/StateRepro/crawler/reproducer/qemu/bzImage_kasan", "-append"])
        if opts is None:
            cur_opts.extend(def_opts)
        else:
            cur_opts.extend(opts)
        if type(cur_opts) == list:
            self.cmd_launch.append(" ".join(cur_opts))
        self.logger.info(self.cmd_launch)
        return

    def _disable_snapshot_in_cmd(self):
        cmd = []
        lengh = len(self.cmd_launch)
        if lengh == 0:
            return
        for i in range(0, lengh):
            key = self.cmd_launch[i]
            if key != '-snapshot':
                cmd.append(key)
        self.cmd_launch = cmd

    def _enable_snapshot_in_cmd(self):
        cmd = []
        lengh = len(self.cmd_launch)
        if lengh == 0:
            return
        for i in range(0, lengh):
            key = self.cmd_launch[i]
            if key == '-kernel':
                cmd.append('-snapshot')
            cmd.append(key)
        self.cmd_launch = cmd

    @log_thread
    def _prepare_alternative_func(self):
        try:
            ret = self.alternative_func(self, *self.alternative_func_args)
            self._send_return_value(ret)
        except Exception as e:
            self.logger.error("alternative_func failed: {}".format(e))
            self._send_return_value(False)
            tb = traceback.format_exc()
            self.logger.error(tb)
        self.alternative_func_finished = True
        return

    @log_thread
    def _new_output_timer(self):
        while not self.func_finished():
            while (self._output_timer > 0):
                self.lock.acquire()
                self._output_timer -= 1
                self.lock.release()
                if self.instance.poll() is not None:
                    return
                sleep(1)
            if self.instance.poll() is not None:
                return
            self._output_lock.acquire(blocking=True)
        # if not self._has_new_output:
        return

    def _resume_output_timer(self):
        self.lock.acquire()
        self._output_timer = default_output_timer
        self.lock.release()

    @log_thread
    def __log_qemu(self, pipe):
        try:
            self.logger.info("\n".join(self.cmd_launch) + "\n")
            self.logger.info("pid: {}  timeout: {}".format(self.instance.pid, self.timeout))
            for line in iter(pipe.readline, b''):
                self._resume_output_timer()
                if self._output_lock.locked():
                    self._output_lock.release()
                try:
                    line = line.decode("utf-8").strip('\n').strip('\r')
                except:
                    self.logger.info('bytes array \'{}\' cannot be converted to utf-8'.format(line))
                    continue
                if regx_match(reboot_regx, line) or regx_match(port_error_regx, line):
                    self.logger.error("Booting qemu-{} failed".format(self.log_name))
                if 'Dumping ftrace buffer' in line:
                    self.dumped_ftrace = True
                if regx_match(r'Rebooting in \d+ seconds', line):
                    self.kill_qemu = True
                self.logger.info(line)
                self.output.append(line)
        except EOFError:
            # Qemu may crash and makes pipe NULL
            pass
        except ValueError:
            # Traceback (most recent call last):                                                                       │
            # File "/usr/lib/python3.6/threading.py", line 916, in _bootstrap_inner                                  │
            # self.run()                                                                                           │
            # File "/usr/lib/python3.6/threading.py", line 864, in run                                               │
            # self._target(*self._args, **self._kwargs)                                                            │
            # File "/home/xzou017/projects/SyzbotAnalyzer/syzscope/interface/vm/instance.py", line 140, in __log_qemu                                                                                                  │
            # for line in iter(pipe.readline, b''):                                                                │
            # ValueError: PyMemoryView_FromBuffer(): info->buf must not be NULL
            pass
        return
