import os
import time
import concurrent.futures
from crashes.crash_case import *
from reproducer.minimize_feature import *

FEATURE_LOOP_DEVICE = 1 << 0
BUG_REPRODUCE_TIMEOUT = 5 * 60
MAX_BUG_REPRODUCE_TIMEOUT = 4 * 60 * 60


class RawBugReproduce():

    def __init__(self, syz_feature_mini: FeatureConfig, case: Case):
        self.bug_title = ''
        self.root_user = None
        self.results = {}
        self.distro_lock = threading.Lock()
        self.repro_timeout = BUG_REPRODUCE_TIMEOUT
        self.syz_feature = syz_feature_mini
        self.cfg = case.cfg
        self.logger = case.logger
        self.case_hash = case.case_hash
        self.repro_dir = case.work_dir

    def run(self):
        ret = {}
        output = queue.Queue()
        for distro in self.cfg.get_all_kernels():
            self.logger.info("start reproducing bugs on {}".format(distro.distro_name))
            x = threading.Thread(target=self.reproduce_async, args=(distro, output,),
                                 name="{} reproduce_async-{}".format(self.case_hash, distro.distro_name))
            x.start()
            time.sleep(1)

        for _ in self.cfg.get_all_kernels():
            [distro_name, m] = output.get(block=True)
            ret[distro_name] = m

        fail_name = ""
        for key in ret:
            if ret[key]["triggered"]:
                title = ret[key]["bug_title"]
                root = ret[key]["root"]
                if not root:
                    str_privilege = " by normal user"
                else:
                    str_privilege = " by root user"
                self.logger.info("{} triggers a bug: {} {}".format(key, title, str_privilege))
            else:
                fail_name += key + " "
        if fail_name != "":
            self.logger.info("{} fail to trigger the bug".format(fail_name))
        return True

    def reproduce_async(self, distro, q):
        res = {"distro_name": distro.distro_name, "triggered": False, "bug_title": "", "root": True}

        success, _ = self.raw_reproduce(distro, func=self.capture_kasan, timeout=self.repro_timeout + 100,
                                        logger=self.logger)
        if success:
            res["triggered"] = True
            res["bug_title"] = self.bug_title
            res["root"] = True
            success, _ = self.raw_reproduce(distro, func=self.capture_kasan, root=False,
                                            timeout=self.repro_timeout + 100,
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

    def raw_reproduce(self, distro: Vendor, func, func_args=(), **kwargs):
        distro.executor.init_logger(self.logger)
        self.root_user = distro.executor.root_user
        self.logger.info("[root] Booting {}".format(distro.distro_name))
        
        testcase_dir = os.path.join(self.repro_dir, "testcases")
        triggered_once = False
        final_results = []
        
        def run_testcase(testcase_dir):
            cur_testcase_dir = os.path.join(os.path.join(self.repro_dir, "testcases", testcase_dir))
            syz_prog = os.path.join(cur_testcase_dir, "testcase")
            vm_log_path = os.path.join(cur_testcase_dir, "vmlog")
            cover_path = os.path.join(cur_testcase_dir, "cover")
            
            return distro.executor.run_func_monitor_crash(func=func, func_args=func_args,
                                                    is_cprog=False,
                                                    testcase=syz_prog,
                                                    work_dir=cur_testcase_dir,
                                                    vm_tag=distro.distro_name,
                                                    c_hash=self.case_hash,
                                                    log_name=vm_log_path,
                                                    cover_dir=cover_path,
                                                    **kwargs)
        # Use ThreadPoolExecutor to manage multiple test cases concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_testcase = {executor.submit(run_testcase, testcase_dir): testcase_dir
                                for testcase_dir in os.listdir(os.path.join(self.repro_dir, "testcases"))}

            for future in concurrent.futures.as_completed(future_to_testcase):
                testcase_dir = future_to_testcase[future]
                try:
                    report, triggered, t = future.result()
                    if triggered:
                        self.logger.info(f"Test case {testcase_dir} triggered bugs.")
                        title = self._BugChecker(report)
                        self.bug_title = title
                        triggered_once = True
                        final_results.append(t)
                except Exception as exc:
                    self.logger.error(f"Test case {testcase_dir} generated an exception: {exc}")
                    
        self.logger.info(f"{distro.distro_name} triggered bugs: {self.bug_title}")
        return triggered_once, final_results

    def success(self):
        for key in self.results:
            if self.results[key]['trigger']:
                return True
        return False


    def capture_kasan(self, qemu, testcase, is_cprog, cover_dir):
        self._execute(qemu, testcase, is_cprog, cover_dir)
        return
    
    def _execute(self, qemu, testcase, is_cprog, cover_dir):
        if not is_cprog:
            self._execute_syz(qemu, testcase, cover_dir)
        else:
            self._run_poc(qemu, testcase, cover_dir)

    def _execute_syz(self, qemu: VMInstance, testcase, cover_dir):
        user = self.root_user
        syz_execprog = os.path.join("/home/weichen/StateRepro/crawler/syzkaller", "syz-execprog")
        syz_executor = os.path.join("/home/weichen/StateRepro/crawler/syzkaller", "syz-executor")
        vm_testcase_file = "/root/testcase" + os.path.basename(os.path.dirname(testcase))
        qemu.upload(user=user, src=[testcase], dst=vm_testcase_file, wait=True)
        qemu.upload(user=user, src=[syz_execprog, syz_executor], dst="/tmp", wait=True)
        qemu.command(cmds="chmod +x /tmp/syz-execprog /tmp/syz-executor", user=user, wait=True)
        qemu.logger.info("running PoC")
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user=self.root_user, wait=True)
        cmds = self.syz_feature.make_def_syz_command(vm_testcase_file, cover=True)
        qemu.command(cmds=cmds, user=user, wait=True, timeout=self.repro_timeout)
        out = qemu.command(cmds="ls " + vm_testcase_file + "_prog*", user=user, wait=True)
        qemu.command(cmds="killall syz-executor && killall syz-execprog", user="root", wait=True)
        os.makedirs(cover_dir, exist_ok=True)
        cover_files = []
        for line in out:
            line = line.strip()
            if not line.startswith(vm_testcase_file):
                continue
            cover_files.append(line)
        qemu.download(user=user, src=cover_files, dst=cover_dir, wait=True)
        time.sleep(5)
        return qemu.trigger_crash

    def _run_poc(self, qemu, testcase, cover_dir):
        user = self.root_user
        poc_src = "poc_root.c"
        poc_path = os.path.join(self.syzkaller_path, poc_src)
        self._proceed_x86_poc(qemu, user, poc_path, poc_src)
        return

    def _proceed_x86_poc(self, qemu, user, poc_path, poc_src):
        qemu.upload(user=user, src=[poc_path], dst="~/", wait=True)
        qemu.command(cmds="gcc -pthread -o poc {}".format(poc_src), user=user, wait=True)
        qemu.logger.info("running PoC")
        # It looks like scp returned without waiting for all file finishing uploading.
        # Sleeping for 1 second to ensure everything is ready in vm
        time.sleep(1)
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user=self.root_user, wait=True)
        qemu.command(cmds="chmod +x poc && ./poc", user=user, timeout=self.repro_timeout, wait=True)
        qemu.command(cmds="killall poc", user="root", wait=True)

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
                        self.logger.info("Double free")
                        self._write_to(self.path_project, "VendorDoubleFree")
                        flag_double_free = True
                        break
                    if regx_match(kasan_write_addr_regx, line) and not flag_kasan_write:
                        self.logger.info("KASAN MemWrite")
                        self._write_to(self.path_project, "VendorMemWrite")
                        flag_kasan_write = True
                        break
                    if regx_match(kasan_read_addr_regx, line) and not flag_kasan_read:
                        self.logger.info("KASAN MemRead")
                        self._write_to(self.path_project, "VendorMemRead")
                        flag_kasan_read = True
                        break

        return title

    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.syzkaller_path, name)
        super()._write_to(content, file_path)

    def cleanup(self):
        super().cleanup()
