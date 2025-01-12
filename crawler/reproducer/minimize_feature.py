import shutil
from utils import *
from reproducer.qemu.vm import *
from .syzkaller_interface import *

qemu_output_window = 15


class FeatureConfig():
    DEPENDENCY_PLUGINS = []
    SYZ_PROG = 0
    C_PROG = 1
    BOTH_FAIL = 2
    ARG_APPEND = 1
    ARG_ALONE = 0

    def __init__(self, timeout: int, repro_attempt: int):
        super().__init__()
        self.i386 = False
        self.syz: SyzkallerInterface = None
        self.repro_timeout = timeout
        self.repro_attempt = repro_attempt

    def build_upstream_kernel(self):
        if self._check_stamp("BUILD_KERNEL") and not self._check_stamp("BUILD_SYZ_FEATURE_MINIMIZE_KERNEL"):
            self._remove_stamp("BUILD_KERNEL")
        ret = self.build_mainline_kernel(keep_ori_config=True)
        if ret == 0:
            self._create_stamp("BUILD_SYZ_FEATURE_MINIMIZE_KERNEL")
        return ret

    def build_syzkaller(self):
        syz_commit = self.case['syzkaller']
        self._prepare_syz()
        self.syz.prepare_on_demand(self.syzkaller_path)
        if self.syz.pull_syzkaller(commit=syz_commit) != 0:
            self.err_msg("Failed to pull syzkaller")
            return -1
        arch = 'amd64'
        if self.i386:
            arch = '386'
        if self.syz.build_syzkaller(arch=arch) != 0:
            self.err_msg("Failed to build syzkaller")
            return -1
        return 0

    def minimize_syz_feature(self, features, root=True):
        self.report.append("PoC originally requires {}".format(features))
        return self._minimize_syz_feature(features, root)

    def test_two_prog(self, features):
        if self._test_feature(None, features, root=True, repeat=True):
            return self.SYZ_PROG
        if self.has_c_repro and self.test_PoC(features, repeat=True):
            return self.C_PROG
        return self.BOTH_FAIL

    def get_features(self, syz_repro_url):
        syz_repro = request_get(syz_repro_url).text
        self._write_to(syz_repro, "testcase")
        syzbin_folder = 'linux_amd64'
        shutil.copyfile(os.path.join(self.syz.syzkaller_path, 'bin/linux_amd64/syz-execprog'.format(syzbin_folder)),
                        os.path.join(self.syzkaller_path, 'syz-execprog'))
        shutil.copyfile(os.path.join(self.syz.syzkaller_path, 'bin/{}/syz-executor'.format(syzbin_folder)),
                        os.path.join(self.syzkaller_path, 'syz-executor'))
        shutil.copyfile(os.path.join(self.syz.syzkaller_path, 'bin/syz-prog2c'),
                        os.path.join(self.syzkaller_path, 'syz-prog2c'))

        features = self._get_syz_features(syz_repro)
        return features

    def run(self):
        if self.build_upstream_kernel() != 0:
            self.err_msg("Failed to build upstream kernel")
            return False
        if self.build_syzkaller() < 0:
            self.err_msg('Failed to build syzkaller')
            return False
        features = self.get_features()
        prog_status = self.test_two_prog(features)
        features['prog_status'] = prog_status
        self.results = features
        self.info_msg("self.results: {} {}".format(self.results, self))
        features, rule_out = self.minimize_syz_feature(features)
        self._write_to("\n".join(rule_out), "rule_out_features")
        return self.generate_new_PoC(features)

    def test_PoC(self, features: list, repeat=False):
        if not self._test_feature(None, features, root=True, test_c_prog=True, repeat=repeat):
            return False
        return True

    def generate_new_PoC(self, features):
        self.info_msg("Generating PoC_repeat.c and PoC_no_repeat.c")
        syz_prog_path = os.path.join(self.syzkaller_path, 'testcase')
        prog2c_cmd = self._make_prog2c_command(syz_prog_path, features, self.i386)
        self.logger.info("syz-prog2c for PoC_repeat: {}".format(prog2c_cmd))
        local_command(command='chmod +x syz-prog2c && {} > {}/PoC_repeat.c'.format(prog2c_cmd, self.syzkaller_path),
                      logger=self.logger, \
                      shell=True, cwd=self.syz.syzkaller_path)
        if self._file_is_empty(os.path.join(self.syzkaller_path, "PoC_repeat.c")):
            return False
        shutil.copyfile(os.path.join(self.syzkaller_path, "PoC_repeat.c"),
                        os.path.join(self.path_case, "PoC_repeat.c"))

        prog2c_cmd = self._make_prog2c_command(syz_prog_path, features, self.i386, repeat=False)
        self.logger.info("syz-prog2c for PoC_no_repeat: {}".format(prog2c_cmd))
        local_command(
            command='chmod +x syz-prog2c && {} > {}/PoC_no_repeat.c'.format(prog2c_cmd, self.syzkaller_path),
            logger=self.logger, \
            shell=True, cwd=self.syz.syzkaller_path)
        if self._file_is_empty(os.path.join(self.syzkaller_path, "PoC_no_repeat.c")):
            return False
        shutil.copyfile(os.path.join(self.syzkaller_path, "PoC_no_repeat.c"),
                        os.path.join(self.path_case, "PoC_no_repeat.c"))
        return True

    def generate_report(self):
        final_report = "\n".join(self.report)
        self.info_msg(final_report)
        self._write_to(final_report, self.REPORT_NAME)

    def _write_to(self, content, name):
        file_path = "{}/{}".format(self.syzkaller_path, name)
        super()._write_to(content, file_path)

    def cleanup(self):
        super().cleanup()

    def _file_is_empty(self, file):
        return open(file, 'r').read() == ''

    def _get_syz_features(self, syz_repro):
        features = {}
        for line in syz_repro.split('\n'):
            if line.find('{') != -1 and line.find('}') != -1:
                try:
                    pm = json.loads(line[1:])
                except json.JSONDecodeError:
                    self.case_logger.info("Using old syz_repro")
                    pm = syzrepro_convert_format(line[1:])

                for each in ["tun", "binfmt_misc", "cgroups", "close_fds", "devlinkpci", "netdev", "resetnet", "usb",
                             "ieee802154", "sysctl", "vhci", "wifi"]:
                    if each in pm:
                        features[each] = pm[each]
                break
        self.info_msg("features: {}".format(features))
        for each in features:
            self.results[each] = features[each]
        return features

    def get_def_syz_feature(self):
        features = {}
        for each in ["tun", "binfmt_misc", "cgroups", "close_fds", "devlinkpci", "netdev", "resetnet", "usb",
                     "ieee802154", "sysctl", "vhci", "wifi"]:
            features[each] = 1
        return features

    def _minimize_syz_feature(self, features: list, root):
        rule_out = []
        essential_features = features.copy()
        for rule_out_feature in features:
            if features[rule_out_feature]:
                if self._test_feature(rule_out_feature, essential_features, repeat=True, root=root):
                    essential_features[rule_out_feature] = False
                    rule_out.append(rule_out_feature)
        essential_features['no_sandbox'] = True
        if not self._test_feature(None, essential_features, repeat=True, root=root):
            essential_features['no_sandbox'] = False
        self.results = essential_features
        return essential_features, rule_out

    def _test_feature(self, rule_out_feature, essential_features: list, root, test_c_prog=False, repeat=False,
                      sandbox=""):
        self.info_msg("=======================================")
        self.info_msg("Testing ruling out feature: {}".format(rule_out_feature))
        self.info_msg("Testing essential feature: {}".format(essential_features))
        new_features = essential_features.copy()
        if rule_out_feature in new_features:
            new_features[rule_out_feature] = False
        distro = self.cfg.get_kernel_by_name(self.kernel)
        if distro == None:
            self.logger.exception("Fail to get {} kernel".format(self.kernel))
            return False
        self.root_user = distro.repro.root_user
        self.normal_user = distro.repro.normal_user
        distro.repro.init_logger(self.logger)
        _, triggered, _ = distro.repro.raw_reproduce(func=self._capture_crash,
                                                     func_args=(new_features, test_c_prog, repeat, sandbox),
                                                     vm_tag='test feature {}'.format(rule_out_feature), \
                                                     timeout=self.repro_timeout + 100, attempt=self.repro_attempt,
                                                     root=root, work_dir=self.syzkaller_path, c_hash=self.case_hash)
        self.info_msg("crash triggered: {}".format(triggered))
        return triggered

    def _capture_crash(self, qemu: VM, root: bool, features: list, test_c_prog: bool, repeat: bool, sandbox: str):
        if root:
            user = self.root_user
        else:
            user = self.normal_user

        syz_prog_path = os.path.join(self.syzkaller_path, 'testcase')
        if root:
            qemu.upload(user=user, src=[syz_prog_path], dst='/root', wait=True)
        else:
            qemu.upload(user=user, src=[syz_prog_path], dst='/home/{}'.format(user), wait=True)
        qemu.command(cmds="echo \"6\" > /proc/sys/kernel/printk", user='root', wait=True)

        if test_c_prog:
            prog2c_cmd = self._make_prog2c_command(syz_prog_path, features, self.i386, repeat=repeat)
            local_command(command='chmod +x syz-prog2c && {} > {}/poc.c'.format(prog2c_cmd, self.syzkaller_path),
                          logger=self.logger, \
                          shell=True, cwd=self.syz.syzkaller_path)
            self.info_msg("Convert syz-prog to c prog: {}".format(prog2c_cmd))
            qemu.upload(user=user, src=[os.path.join(self.syzkaller_path, 'poc.c')], dst='/root', wait=True)
            if self.i386:
                qemu.command(cmds="gcc -m32 -pthread -o poc poc.c", user=user, wait=True)
            else:
                qemu.command(cmds="gcc -pthread -o poc poc.c", user=user, wait=True)

            qemu.command(cmds="./poc", user=user, wait=True, timeout=self.repro_timeout)
        else:
            executor_path = os.path.join(self.syzkaller_path, 'syz-executor')
            execprog_path = os.path.join(self.syzkaller_path, 'syz-execprog')
            qemu.upload(user=user, src=[execprog_path, executor_path], dst='/tmp', wait=True)
            qemu.command(cmds="chmod +x /tmp/syz-executor && chmod +x /tmp/syz-execprog", user=user, wait=True,
                         timeout=self.repro_timeout)

            syz_prog = open(syz_prog_path, 'r').readlines()
            cmd = self.make_syz_command(syz_prog, features, self.i386, repeat=repeat, sandbox=sandbox, root=root)
            self.info_msg("syz command: {}".format(cmd))
            qemu.command(cmds=cmd, user=user, wait=True, timeout=self.repro_timeout)
        return

    def _extract_prog_options(self, prog):
        options = {}
        out = local_command(command="chmod +x {0} && {0} -h".format(prog), shell=True, cwd=self.syzkaller_path)
        for line in out:
            if regx_match(r'^( )+-([a-z0-9A-Z_]+)', line):
                op = regx_get(r'^( )+-([a-z0-9A-Z_]+)', line, 1)
                if op is not None:
                    if regx_match(r'^( )+-([a-z0-9A-Z_]+ [a-z0-9A-Z_]+)', line):
                        options[op] = self.ARG_APPEND
                    else:
                        options[op] = self.ARG_ALONE
        return options

    def _make_prog2c_command(self, testcase_path, features: dict, i386: bool, repeat=True):
        command = "./syz-prog2c -prog {} ".format(testcase_path)
        text = open(testcase_path, 'r').readlines()
        options = self._extract_prog_options('./syz-prog2c')
        opt = {}

        enabled = "-enable="
        disable = "-disable="
        normal_pm = {"arch": "amd64", "threaded": "false", "collide": "false", "sandbox": "none", "fault_call": "-1",
                     "fault_nth": "0", "tmpdir": "false", "segv": "false", "slowdown": "1"}
        for line in text:
            if line.find('{') != -1 and line.find('}') != -1:
                try:
                    pm = json.loads(line[1:])
                except json.JSONDecodeError:
                    pm = syzrepro_convert_format(line[1:])
                for each in normal_pm:
                    if each in pm and pm[each] != "" and each in options:
                        if each == "sandbox" and 'no_sandbox' in features and features['no_sandbox']:
                            continue
                        opt[each] = str(pm[each]).lower()

                        if each == "sandbox" and str(pm[each]).lower() != "none":
                            opt['tmpdir'] = "true"
                    else:
                        if each == 'arch' and i386:
                            opt[each] = "386"
                if repeat:
                    opt['repeat'] = "0"
                    if "procs" in pm and str(pm["procs"]) != "1":
                        num = int(pm["procs"])
                        opt['procs'] = str(num)
                    else:
                        opt['procs'] = "1"
                else:
                    opt['repeat'] = "1"
                    opt['procs'] = "1"
                # command += "-trace "
                # It makes no sense that limiting the features of syz-execrpog, just enable them all
                if self._support_enable_feature():
                    if "tun" in features:
                        if features['tun']:
                            enabled += "tun,"
                            if '-sandbox' not in command:
                                opt['sandbox'] = "none"
                            if '-tmpdir' not in command:
                                opt['tmpdir'] = "true"
                    if "binfmt_misc" in features:
                        if features["binfmt_misc"]:
                            enabled += "binfmt_misc,"
                            if '-sandbox' not in command:
                                opt['sandbox'] = "none"
                            if '-tmpdir' not in command:
                                opt['tmpdir'] = "true"
                    if "cgroups" in features:
                        if features["cgroups"]:
                            enabled += "cgroups,"
                            if '-sandbox' not in command:
                                opt['sandbox'] = "none"
                            if '-tmpdir' not in command:
                                opt['tmpdir'] = "true"
                    if "close_fds" in features:
                        if features["close_fds"]:
                            enabled += "close_fds,"
                    if "devlinkpci" in features:
                        if features["devlinkpci"]:
                            enabled += "devlink_pci,"
                    if "netdev" in features:
                        if features["netdev"]:
                            enabled += "net_dev,"
                            opt['sandbox'] = "namespace"
                    if "resetnet" in features:
                        if features["resetnet"]:
                            enabled += "net_reset,"
                            opt['repeat'] = "0"
                    if "usb" in features:
                        if features["usb"]:
                            enabled += "usb,"
                    if "ieee802154" in features:
                        if features["ieee802154"]:
                            enabled += "ieee802154,"
                    if "sysctl" in features:
                        if features["sysctl"]:
                            enabled += "sysctl,"
                    if "vhci" in features:
                        if features["vhci"]:
                            enabled += "vhci,"
                            if '-sandbox' not in command:
                                opt['sandbox'] = "none"
                            if '-tmpdir' not in command:
                                opt['tmpdir'] = "true"
                    if "wifi" in features:
                        if features["wifi"]:
                            enabled += "wifi,"
                            if '-sandbox' not in command:
                                opt['sandbox'] = "none"
                            if '-tmpdir' not in command:
                                opt['tmpdir'] = "true"
                break
        for key in opt:
            if key == "repeat":
                # specially handle repeat cuz the weird argument setup in historic syz-execprog and syz-prog2c
                if opt[key] == "1":
                    continue
                if opt[key] == "0" and options[key] == self.ARG_ALONE:
                    command += "-" + key + " "
                else:
                    command += "-" + key + "=" + opt[key] + " "
            else:
                command += "-" + key + "=" + opt[key] + " "
        if self._support_enable_feature():
            if enabled[-1] == ',':
                enabled = enabled[:-1]
                command += enabled + " "
            if disable[-1] == ',':
                disable = disable[:-1]
                command += disable + " "
        command += "testcase"
        return command

    def make_def_syz_command(self, testcase_path: str, cover: bool):
        command = "/tmp/syz-execprog -executor=/tmp/syz-executor "
        # ./syz-execprog -executor=./syz-executor -arch=amd64 -sandbox=none -procs=1 -repeat=1
        #                -threaded=false -collide=false -optional=slowdown=1:type=qemu
        default_pm = {"arch": "amd64", "threaded": "false",
                      "collide": "false", "sandbox": "none",
                      "slowdown": "1", "procs": 1, "repeat": 1,
                      "cover": 1, "coverfile": testcase_path}
        for key in default_pm:
            command += "-" + key + "=" + str(default_pm[key]) + " "
        command += testcase_path
        return command
    
    def make_repeat_syz_command(self, testcase_path: str, cover: bool):
        command = "/tmp/syz-execprog -executor=/tmp/syz-executor "
        # ./syz-execprog -executor=./syz-executor -arch=amd64 -sandbox=none -procs=8 -repeat=3 -threaded=true 
        # -collide=false -cover=1 -coverfile=/syzkaller3052270408 -optional=slowdown=1:sandboxArg=0:type=qemu ./usbconnect 
        default_pm = {"arch": "amd64", "threaded": "true",
                      "collide": "false", "sandbox": "none",
                      "slowdown": "1", "procs": 1, "repeat": 3,
                      "cover": 1, "coverfile": testcase_path}
        for key in default_pm:
            command += "-" + key + "=" + str(default_pm[key]) + " "
        command += testcase_path
        return command

    def make_syz_command(self, text, features: list, i386: bool, repeat=None, sandbox="", root=True):
        command = "/tmp/syz-execprog -executor=/tmp/syz-executor "
        opt = {}
        options = self._extract_prog_options('./syz-execprog')
        if text[0][:len(command)] == command:
            # If read from repro.command, text[0] was already the command
            return text[0]
        enabled = "-enable="
        normal_pm = {"arch": "amd64", "threaded": "false", "collide": "false", "sandbox": "none", "fault_call": "-1",
                     "fault_nth": "0", "slowdown": "1"}
        for line in text:
            if line.find('{') != -1 and line.find('}') != -1:
                try:
                    pm = json.loads(line[1:])
                except json.JSONDecodeError:
                    pm = syzrepro_convert_format(line[1:])
                for each in normal_pm:
                    if each in pm and pm[each] != "" and each in options:
                        if each == "sandbox":
                            if sandbox != "":
                                opt[each] = sandbox
                                continue
                            if 'no_sandbox' in features and features['no_sandbox']:
                                continue
                        opt[each] = str(pm[each]).lower()
                    else:
                        if each == 'arch' and i386:
                            opt[each] = "386"
                        else:
                            if each == "sandbox":
                                if sandbox != "":
                                    opt[each] = sandbox
                                    continue
                                if 'no_sandbox' in features and features['no_sandbox']:
                                    continue
                if "procs" in pm and str(pm["procs"]) != "1":
                    num = int(pm["procs"])
                    if num < 6:
                        num = 3
                    else:
                        opt['procs'] = str(num * 2)
                else:
                    if repeat:
                        opt['procs'] = "6"
                    else:
                        opt['procs'] = "1"

                if repeat is None:
                    if "repeat" in pm and pm["repeat"] != "":
                        if pm["repeat"] == "0" or pm["repeat"] == True or pm["repeat"] == "true":
                            opt['repeat'] = "0"
                            repeat = True
                        if pm["repeat"] == "1" or pm["repeat"] == False or pm["repeat"] == "false":
                            opt['repeat'] = "1"
                elif repeat:
                    opt['repeat'] = "0"
                else:
                    opt['repeat'] = "1"
                # It makes no sense that limiting the features of syz-execrpog, just enable them all
                if self._support_enable_feature():
                    if "tun" in features and features["tun"]:
                        enabled += "tun,"
                        opt['sandbox'] = "namespace"
                    if "binfmt_misc" in features and features["binfmt_misc"]:
                        enabled += "binfmt_misc,"
                    if "cgroups" in features and features["cgroups"]:
                        enabled += "cgroups,"
                    if "close_fds" in features and features["close_fds"]:
                        enabled += "close_fds,"
                    if "devlinkpci" in features and features["devlinkpci"] and root:
                        enabled += "devlink_pci,"
                    if "netdev" in features and features["netdev"]:
                        enabled += "net_dev,"
                        opt['sandbox'] = "namespace"
                    if "resetnet" in features and features["resetnet"]:
                        enabled += "net_reset,"
                        opt['repeat'] = "0"
                    if "usb" in features and features["usb"]:
                        enabled += "usb,"
                    if "ieee802154" in features and features["ieee802154"]:
                        enabled += "ieee802154,"
                    if "sysctl" in features and features["sysctl"]:
                        enabled += "sysctl,"
                    if "vhci" in features and features["vhci"]:
                        enabled += "vhci,"
                    if "wifi" in features and features["wifi"]:
                        enabled += "wifi,"
                break
        if self._support_enable_feature():
            if not root and enabled == "-enable=" and '-sandbox=namespace' not in command:
                opt['disable'] = "tun,devlink_pci"
        for key in opt:
            if key == "repeat":
                # specially handle repeat cuz the weird argument setup in historic syz-execprog and syz-prog2c
                if opt[key] == "1":
                    continue
                if opt[key] == "0" and options[key] == self.ARG_ALONE:
                    command += "-" + key + " "
                else:
                    command += "-" + key + "=" + opt[key] + " "
            else:
                command += "-" + key + "=" + opt[key] + " "
        if self._support_enable_feature():
            if enabled[-1] == ',':
                enabled = enabled[:-1]
                command += enabled + " "
        command += "testcase"
        return command

    def _prepare_syz(self):
        self.syz = self._init_module(SyzkallerInterface())

    def _support_enable_feature(self):
        if self.syz == None:
            if self.build_syzkaller() < 0:
                self.err_msg('Failed to build syzkaller')
                return False
        return self.syz.support_enable_feature()
