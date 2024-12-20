from audioop import reverse
import queue
import re, os, time, shutil, threading

from analysis_module import AnalysisModule
from qemu.vm import VMInstance
from utils import *
from strings import *
from subprocess import Popen, STDOUT, PIPE, call
from minimize_feature import SyzFeatureMinimize

BUG_REPRODUCE_TIMEOUT = 5 * 60
MAX_BUG_REPRODUCE_TIMEOUT = 4 * 60 * 60


class RawBugReproduce(AnalysisModule):
    NAME = "RawBugReproduce"
    REPORT_START = "======================RawBugReproduce Report======================"
    REPORT_END = "==================================================================="
    REPORT_NAME = "Report_RawBugReproduce"
    DEPENDENCY_PLUGINS = ["SyzFeatureMinimize"]

    FEATURE_LOOP_DEVICE = 1 << 0

    def __init__(self, syz_feature_mini: SyzFeatureMinimize):
        super().__init__()
        self.bug_title = ''
        self.root_user = None
        self.normal_user = None
        self.distro_lock = threading.Lock()
        self.repro_timeout = BUG_REPRODUCE_TIMEOUT
        self.syz_feature = {}
        self.syz_feature_mini = syz_feature_mini
        self.c_prog = True
        self._init_results()


    def check(func):
        def inner(self):
            ret = func(self)
            fail_name = ""
            for key in ret:
                if ret[key]["triggered"]:
                    title = ret[key]["bug_title"]
                    root = ret[key]["root"]
                    if not root:
                        str_privilege = " by normal user"
                    else:
                        str_privilege = " by root user"
                    self.main_logger.info("{} triggers a bug: {} {}".format(key, title, str_privilege))
                    self.report.append("{} triggers a bug: {} {}".format(key, title, str_privilege))
                    self.set_stage_text("Triggered")
                    self._move_to_success = True
                else:
                    fail_name += key + " "
            if fail_name != "":
                self.main_logger.info("{} fail to trigger the bug".format(fail_name))
                self.report.append("{} fail to trigger the bug".format(fail_name))
                self.set_stage_text("Failed")
            return True

        return inner

    @check
    def run(self):
        res = {}
        output = queue.Queue()
        self.syz_feature_mini.path_case_plugin = os.path.join(self.path_case, SyzFeatureMinimize.NAME)
        if not self.has_c_repro:
            self.c_prog = False
        # if not self.plugin_finished("SyzFeatureMinimize"):
        #     self.info_msg("RawBugReproduce will use C Prog instead")
        #     if not self.has_c_repro:
        #         return False
        if not self.c_prog:
            self.syz_feature = self.syz_feature_mini.results.copy()
            self.logger.info("Receive syz_feature: {} {}".format(self.syz_feature, self.syz_feature_mini))
            self.syz_feature.pop('prog_status')
        for distro in self.cfg.get_distros_and_android():
            self.info_msg("start reproducing bugs on {}".format(distro.distro_name))
            x = threading.Thread(target=self.reproduce_async, args=(distro, output),
                                 name="{} reproduce_async-{}".format(self.case_hash, distro.distro_name))
            x.start()
            time.sleep(1)
            if self.debug:
                x.join()

        for _ in self.cfg.get_distros_and_android():
            [distro_name, m] = output.get(block=True)
            res[distro_name] = m
        return res

    def reproduce_async(self, distro, q):
        res = {}
        res["distro_name"] = distro.distro_name
        res["triggered"] = False
        res["bug_title"] = ""
        res["root"] = True

        success, _ = self.reproduce(distro, func=self.capture_kasan, root=True, timeout=self.repro_timeout + 100,
                                    logger=self.logger)
        if success:
            res["triggered"] = True
            res["bug_title"] = self.bug_title
            res["root"] = True
            success, _ = self.reproduce(distro, func=self.capture_kasan, root=False, timeout=self.repro_timeout + 100,
                                        logger=self.logger)
            if success:
                res["triggered"] = True
                res["bug_title"] = self.bug_title
                res["root"] = False
            self.results[distro.distro_name]['root'] = res['root']
            self.results[distro.distro_name]['trigger'] = True
            q.put([distro.distro_name, res])
            return

        q.put([distro.distro_name, res])
        self.logger.info("Thread for {} finished".format(distro.distro_name))
        return

    def reproduce(self, distro, root: bool, func, func_args=(), log_prefix="qemu", **kwargs):
        if root:
            self.set_stage_text("\[root] Booting {}".format(distro.distro_name))
        else:
            self.set_stage_text("\[user] Booting {}".format(distro.distro_name))

        self.tune_poc(root)
        if root:
            log_name = "{}-{}-root".format(log_prefix, distro.distro_name)
        else:
            log_name = "{}-{}-normal".format(log_prefix, distro.distro_name)
        distro.repro.init_logger(self.logger)
        self.root_user = distro.repro.root_user
        self.normal_user = distro.repro.normal_user
        report, triggered, t = distro.repro.reproduce(func=func, func_args=func_args, root=root,
                                                      work_dir=self.path_case_plugin, vm_tag=distro.distro_name,
                                                      c_hash=self.case_hash, log_name=log_name, **kwargs)
        self.info_msg("{} triggered bugs: {}".format(distro.distro_name, triggered))
        if triggered:
            title = self._BugChecker(report)
            self.bug_title = title
            return triggered, t
        return False, t

    def tune_poc(self, root: bool):
        feature = 0

        src = os.path.join(self.path_case, "poc.c")
        if not root:
            dst = os.path.join(self.path_case_plugin, "poc_normal.c")
        else:
            dst = os.path.join(self.path_case_plugin, "poc_root.c")

        shutil.copyfile(src, dst)
        # self._compile_poc(root)
        return feature

    def success(self):
        for key in self.results:
            if self.results[key]['trigger']:
                return True
        return False

    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)

    def _execute(self, qemu, root):
        if not self.c_prog:
            self._execute_syz(qemu, root)
        else:
            self._run_poc(qemu, root)

    def capture_kasan(self, qemu, root):
        self._execute(qemu, root)
        return

    def set_history_status(self):
        for name in self.results:
            if self.results[name]['trigger']:
                self.set_stage_text("Triggered")
                return
        self.set_stage_text("Failed")

    def _execute_syz(self, qemu: VMInstance, root):
        if root:
            user = self.root_user
        else:
            user = self.normal_user
        syz_feature_mini_path = os.path.join(self.path_case, "SyzFeatureMinimize")
        i386 = False
        if '386' in self.case['manager']:
            i386 = True
        syz_execprog = os.path.join(syz_feature_mini_path, "syz-execprog")
        syz_executor = os.path.join(syz_feature_mini_path, "syz-executor")
        testcase = os.path.join(self.path_case, "testcase")
        qemu.upload(user=user, src=[testcase], dst="~/", wait=True)
        qemu.upload(user=user, src=[syz_execprog, syz_executor], dst="/tmp", wait=True)
        qemu.command(cmds="chmod +x /tmp/syz-execprog /tmp/syz-executor", user=user, wait=True)
        qemu.logger.info("running PoC")
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user=self.root_user, wait=True)
        testcase_text = open(testcase, "r").readlines()

        cmds = self.syz_feature_mini.make_syz_command(testcase_text, self.syz_feature, i386, repeat=None, root=root)
        qemu.command(cmds=cmds, user=user, wait=True, timeout=self.repro_timeout)
        qemu.command(cmds="killall syz-executor && killall syz-execprog", user="root", wait=True)

        time.sleep(5)
        return qemu.trigger_crash

    def _run_poc(self, qemu, root):
        if root:
            user = self.root_user
            poc_src = "poc_root.c"
        else:
            user = self.normal_user
            poc_src = "poc_normal.c"
        poc_path = os.path.join(self.path_case_plugin, poc_src)
        if self._is_android(qemu):
            self._proceed_android_poc(qemu, poc_path)
        else:
            self._proceed_x86_poc(qemu, user, poc_path, poc_src)
        return

    def _is_android(self, qemu):
        return qemu.kernel.type == 2

    def _proceed_android_poc(self, qemu, poc_path):
        compiler = qemu.kernel.cross_compiler
        if '386' in self.case['manager']:
            cmd = compiler + " -m32"
        else:
            cmd = compiler
        cmd += " -pthread -o /tmp/poc {} -static".format(poc_path)
        local_command(cmd, shell=True, logger=self.logger)
        qemu.upload(src='/tmp/poc', dst='/data/local/tmp', user='', wait=True)
        qemu.command(cmds='/data/local/tmp/poc', timeout=self.repro_timeout, user='', wait=True)

    def _proceed_x86_poc(self, qemu, user, poc_path, poc_src):
        qemu.upload(user=user, src=[poc_path], dst="~/", wait=True)
        if '386' in self.case['manager']:
            qemu.command(cmds="gcc -m32 -pthread -o poc {}".format(poc_src), user=user, wait=True)
        else:
            qemu.command(cmds="gcc -pthread -o poc {}".format(poc_src), user=user, wait=True)
        qemu.logger.info("running PoC")
        # It looks like scp returned without waiting for all file finishing uploading.
        # Sleeping for 1 second to ensure everything is ready in vm
        time.sleep(1)
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user=self.root_user, wait=True)
        qemu.command(cmds="chmod +x poc && ./poc", user=user, timeout=self.repro_timeout, wait=True)
        qemu.command(cmds="killall poc", user="root", wait=True)

    def _init_results(self):
        for distro in self.cfg.get_distros_and_android():
            distro_result = {}

            distro_result['missing_module'] = []
            distro_result['skip_funcs'] = []
            distro_result['device_tuning'] = []
            distro_result['interface_tuning'] = []
            distro_result['namespace'] = False
            distro_result['root'] = None
            distro_result['minimized'] = False
            distro_result['hash'] = self.case['hash']
            distro_result['trigger'] = False
            self.results[distro.distro_name] = distro_result

    def _BugChecker(self, report):
        title = None
        flag_double_free = False
        flag_kasan_write = False
        flag_kasan_read = False
        if report != []:
            try:
                title = report[0][0]
            except IndexError:
                self.err_msg("Bug report error: {}".format(report))
                return None
            if regx_match(r'\[(( )+)?\d+\.\d+\] (.+)', title):
                title = regx_get(r'\[(( )+)?\d+\.\d+\] (.+)', title, 2)
            for each in report:
                for line in each:
                    if regx_match(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line) or \
                            regx_match(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line):
                        m = re.search(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                        m = re.search(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                    if regx_match(double_free_regx, line) and not flag_double_free:
                        self.info_msg("Double free")
                        self._write_to(self.path_project, "VendorDoubleFree")
                        flag_double_free = True
                        break
                    if regx_match(kasan_write_addr_regx, line) and not flag_kasan_write:
                        self.info_msg("KASAN MemWrite")
                        self._write_to(self.path_project, "VendorMemWrite")
                        flag_kasan_write = True
                        break
                    if regx_match(kasan_read_addr_regx, line) and not flag_kasan_read:
                        self.info_msg("KASAN MemRead")
                        self._write_to(self.path_project, "VendorMemRead")
                        flag_kasan_read = True
                        break

        return title

    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.path_case_plugin, name)
        super()._write_to(content, file_path)

    def cleanup(self):
        super().cleanup()