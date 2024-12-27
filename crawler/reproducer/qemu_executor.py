import os
import socket
import queue
import threading
import multiprocessing
import traceback
from strings import *
from reproducer.qemu.vm import *
from utils import *
qemu_output_window = 15


class QemuExecutor:
    def __init__(self, kernel_cfg, case_path, logger):
        self.queue = multiprocessing.Queue()
        self.logger = logger
        self.crash_head = [r'BUG: unable to handle'
                           r'general protection fault', r'KASAN:',
                           r'BUG: kernel NULL pointer dereference']
        self.crash_tail = [r'------------\[ cut here \]------------',
                           r'---\[ end trace [a-zA-Z0-9]+ \]---',
                           r'Rebooting in \d+ seconds..',
                           r'Kernel panic']
        self._setup_crash_capturer()
        
        self.vm_tag = None

        self.logger = logger
        self.kernel = kernel_cfg
        self.image_path = None
        self.vmlinux = None
        self.ssh_key = None
        self.distro_name = ""
        self.case_path = case_path
        self.path_linux = None
        self.index = 0
        self.root_user = None
        self.normal_user = None
        self._setup()
        
    def init_logger(self, logger):
        self.logger = logger

    def prepare_img_bak(self, path_image, th_idx):
        if self.kernel.type == VM.DISTROS:
            self.create_snapshot(self.kernel.distro_image, path_image, self.kernel.distro_name, th_idx)
        if self.kernel.type == VM.UPSTREAM:
            self.create_snapshot(self.kernel.distro_image, path_image, self.kernel.distro_name, th_idx, target_format="raw")

    def get_unused_port(self):
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        so.bind(('localhost', 0))
        _, port = so.getsockname()
        so.close()
        return port

    def _setup(self):
        self.normal_user = self.kernel.normal_user
        self.root_user = self.kernel.root_user
        self.vmtype = self.kernel.type
        if self.vmtype == VM.UPSTREAM:
            self.ssh_key = self.kernel.ssh_key
            self.path_linux = "{}/linux-{}".format(self.case_path, self.kernel.distro_name)
            self.distro_name = self.kernel.distro_name

    def create_snapshot(self, src, img_dir, image_name, th_idx, target_format="qcow2"):
        self.image_path = "{}/{}-snapshot{}.img".format(img_dir, image_name, str(th_idx))
        self.logger.info("Create image {} from {}".format(self.image_path, src))
        if os.path.isfile(self.image_path):
            os.remove(self.image_path)
        cmd = ["qemu-img", "create", "-f", "qcow2", "-b", src, "-F", target_format, self.image_path]
        p = Popen(cmd, stderr=STDOUT, stdout=PIPE)
        exitcode = p.wait()
        return exitcode


    def save_crash_log(self, log_msg, name):
        with open("{}/crash_log-{}".format(self.case_path, name), "w+") as f:
            for each in log_msg:
                for line in each:
                    f.write(line + "\n")
                f.write("\n")

    def run_func_monitor_crash(self, func, func_args, work_dir, timeout, testcase, is_cprog, cover_dir, vm_tag="reproducer", attempt=3, **kwargs):
        res = []
        trigger = False
        remain = []

        i = 0
        error_attempt = 0
        self.vm_tag = vm_tag
        while i < attempt:
            args = {'th_index': i, 'func': func, 'args': func_args, 'testcase': testcase, 'is_cprog': is_cprog,
                    'cover_dir': cover_dir + str(i),
                    'work_dir': work_dir, 'vm_tag': vm_tag + '-' + str(i), 'timeout': timeout, **kwargs}
            x = multiprocessing.Process(target=self._run_and_monitor_crash, kwargs=args,
                                        name="{}-{} trigger-{}".format(kwargs['c_hash'], self.kernel.distro_name,
                                                                       i))
            x.start()
            self.logger.info("Start reproducing {} in process {}, args {}".format(vm_tag + '-' + str(i), x.pid, args))

            t = self.queue.get(block=True)
            if len(t) >= 3:
                crashes = t[0]
                high_risk = t[1]
                qemu_fail = t[2]
                if len(t) > 3:
                    remain = t[3:]
                self.logger.info(
                    "Reproducing done, crashes: {}, high_risk {}, qemu_fail {}".format(crashes, high_risk, qemu_fail))
                if qemu_fail:
                    error_attempt += 1
                    if error_attempt > 3:
                        break
                    continue
            else:
                error_attempt += 1
                self.logger.info("Reproducing failed, ret {}".format(t))
                if error_attempt > 3:
                    break
                continue
            i += 1
            if not trigger and crashes != []:
                trigger = True
                res = crashes
                self.save_crash_log(res, self.distro_name)
                if not res:
                    res = crashes
                break
        if len(res) == 1 and isinstance(res[0], str):
            self.logger.error(res[0])
            return [], trigger, remain
        return res, trigger, remain

    def _run_and_monitor_crash(self, th_index, func, args, testcase, is_cprog, cover_dir, work_dir, vm_tag, timeout, **kwargs):
        self.logger.info("New Process for reproducing {}".format(vm_tag))
        self.prepare_img_bak(work_dir, th_index)
        qemu = self.launch_qemu(tag=vm_tag, log_suffix=str(th_index), work_path=work_dir, timeout=timeout, **kwargs)
        self.logger.info("Launched qemu {}".format(vm_tag))

        self.run_qemu(qemu, self._capture_crash, th_index, work_dir, testcase, is_cprog, cover_dir, timeout, func, *args)
        res = qemu.wait()
        self.logger.info("Qemu {} exit".format(vm_tag))
        if type(res) == bool or (len(res) == 1 and qemu.qemu_fail):
            self.logger.error("Error occur when reproducing {}".format(vm_tag))
            self.queue.put([[], False, True])
        else:
            self.queue.put(res)
        qemu.destroy()

        # sleep 5 seconds to wait qemu to exit
        sleep(5)
        return

    def warp_qemu_capture_crash(self, qemu, q):
        try:
            res, trigger_hunted_bug = self._qemu_capture_crash(qemu)
        except Exception as e:
            self.logger.error("Exception occur when reporducing crash in {}: {}".format(self.vm_tag, e))
            self.logger.error(traceback.format_exc())
            if qemu.instance.poll() is None:
                qemu.instance.kill()
            res = []
            trigger_hunted_bug = False
        # There might be a race condition in between _qemu_capture_kasan and tweak_modules
        # the queue 'q' put data after lock was released, tweak_modules has chance that assume
        # the queue is empty and no new output comes out of QEMU and thus have a wrong module
        # The race window is relatively small, I choose to ignore it to keep our function design
        # Will solve this problem if this race happens in real world
        q.put([res, trigger_hunted_bug])
        return

    def _crash_start(self, line):
        for each in self.crash_head:
            if regx_match(each, line):
                return True
        return False

    def _crash_end(self, line):
        for each in self.crash_tail:
            if regx_match(each, line):
                return True
        return False

    def _qemu_capture_crash(self, qemu: VM):
        qemu_close = False
        out_begin = 0
        record_flag = 0
        crash_flag = 0
        crash = []
        res = []
        trigger_hunted_bug = False
        while not qemu_close:
            if qemu.instance.poll() is not None:
                qemu_close = True
            out_end = len(qemu.output)
            for line in qemu.output[out_begin:]:
                if regx_match(boundary_regx, line) or \
                        self._crash_start(line):
                    record_flag ^= 1
                    if crash_flag == 1 and crash != []:
                        if not self.crash_title_check(qemu, crash):
                            crash = []
                        else:
                            res.append(crash)
                            crash = []
                            trigger_hunted_bug = True
                            qemu.kill_qemu = True
                            qemu.trigger_crash = True
                            break
                    crash_flag = 0
                if regx_match(call_trace_regx, line) or \
                        regx_match(message_drop_regx, line):
                    crash_flag = 1
                if record_flag:
                    crash.append(line)
                if  self._crash_end(line) or \
                        (self._crash_start(line) and crash_flag):
                    if crash_flag == 1 and crash != []:
                        if not self.crash_title_check(qemu, crash):
                            crash = []
                        else:
                            res.append(crash)
                            crash = []
                            trigger_hunted_bug = True
                            qemu.kill_qemu = True
                            qemu.trigger_crash = True
                            break
                    record_flag = 0
                    crash_flag = 0
                    continue
            out_begin = out_end
        return res, trigger_hunted_bug

    def crash_title_check(self, qemu, report):
        title = report[0]
        if boundary_regx in title:
            title = report[1]
        if qemu.kernel.include:
            for each in qemu.kernel.include:
                if each in title:
                    return True
        if qemu.kernel.exclude:
            for each in qemu.kernel.exclude:
                if each in title:
                    return False
        return True

    def _kernel_config_pre_check(self, qemu, config):
        out = qemu.command(cmds="ls /boot/config-`uname -r`".format(config), user=self.root_user, wait=True)
        if 'No such file or directory' in out[1]:
            # If no config file found, normally it's upstream kernel
            return True
        out = qemu.command(cmds="grep {} /boot/config-`uname -r`".format(config), user=self.root_user, wait=True)
        for line in out:
            line = line.strip()
            if line == config:
                self.logger.info("{} is enabled".format(config))
                return True
        return False

    def _wrap_main_func(self, main_func_q, func, *args):
        ret = func(*args)
        main_func_q.put(ret)
        return

    def _setup_crash_capturer(self):
        try:
            head = self.kernel.crash_head
            self.crash_head = head
        except AttributeError:
            pass

        try:
            tail = self.kernel.crash_tail
            self.crash_head = tail
        except AttributeError:
            pass
        return

    def _capture_crash(self, qemu, th_index, work_dir, testcase, is_cprog, cover_dir, timeout, func, *args):
        qemu_queue = queue.Queue()
        threading.Thread(target=self.warp_qemu_capture_crash, args=(qemu, qemu_queue), name="qemu_crash_capturer",
                         daemon=True).start()
        """"
        if not self._kernel_config_pre_check(qemu, "CONFIG_KASAN=y"):
            self.logger.fatal("KASAN is not enabled in kernel!")
            raise KASANDoesNotEnabled(qemu.tag)
        """

        main_func_q = queue.Queue()
        main = threading.Thread(target=self._wrap_main_func, args=(main_func_q, func, qemu, testcase, is_cprog, cover_dir) + args, daemon=True)
        main.start()

        n = int(timeout / qemu_output_window)
        for _ in range(0, n):
            try:
                [res, trigger] = qemu_queue.get(block=True, timeout=qemu_output_window)
                if trigger:
                    try:
                        main_ret = main_func_q.get(block=True, timeout=10)
                    except queue.Empty:
                        self.logger.error("crash capturer has finished but PoC is still running ")
                        main_ret = None
                    self.logger.info("Reproduce finished, triggered the bug")
                    return [res, trigger, qemu.qemu_fail, main_ret]
            except queue.Empty:
                if qemu.no_new_output() and not main.is_alive() and not qemu.trigger_crash:
                    break
        try:
            main_ret = main_func_q.get(block=True, timeout=10)
        except queue.Empty:
            self.logger.error("crash capturer has finished but PoC is still running ")
            main_ret = None
        self.logger.info("Reproduce finished, didn't trigger bug")
        return [[], False, qemu.qemu_fail, main_ret]

    def launch_qemu(self, c_hash=0, log_suffix="", log_name=None, timeout=None, enable_gdb=False, enable_qemu_mon=False,
                    gdb_port=None, mon_port=None, ssh_port=None, **kwargs):
        if log_name is None:
            log_name = "qemu-{0}-{1}.logger.info".format(c_hash, self.distro_name)
        if ssh_port is None:
            ssh_port = self.get_unused_port()
        if not enable_gdb:
            gdb_port = -1
        elif gdb_port is None:
            gdb_port = self.get_unused_port()
        if not enable_qemu_mon:
            mon_port = -1
        elif mon_port is None:
            mon_port = self.get_unused_port()
        qemu = VM(kernel=self.kernel, hash_tag=c_hash, vmlinux=self.vmlinux, port=ssh_port,
                  gdb_port=gdb_port, mon_port=mon_port, image=self.image_path, log_name=log_name,
                  log_suffix=log_suffix, key=self.ssh_key, timeout=timeout, debug=True, **kwargs)
        qemu.logger.info("QEMU-{} launched.\n".format(log_suffix))
        return qemu

    def run_qemu(self, qemu: VM, func, *args):
        return qemu.run(alternative_func=func, args=(*args,))

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

