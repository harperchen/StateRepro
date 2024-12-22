import shutil
import traceback

from crashes.config import Config
from utils import *
from dateutil import parser as time_parser
from errors import *

logger = logging.getLogger(__name__)


class AnalysisModule:
    NAME = "MainAnalysisModule"
    ERROR = 0
    INFO = 1
    DEBUG = 2

    def __init__(self):
        self.logger = logger
        self.finish = False
        self.results = {}
        self.report = []
        self.syzkaller_path = '/home/weichen/StateRepro/crawler/syzkaller'
        self._prepared = False
        self._move_to_success = False
        self._move_to_success = False
        self._analyzor = None

    def init(self, manager):
        self.case = manager.report
        self.kernel = "upstream"
        self.case_hash = manager.case_hash
        self.case_logger = manager.logger
        self.cfg: Config = manager.cfg
        self.path_case = manager.path_case
        self.index = manager.index
        self.debug = manager.debug
        self.logger = self.case_logger


    @property
    def name(self):
        if self.analyzor == None:
            return "NULL"
        return self.analyzor.NAME

    @property
    def analyzor(self):
        return self._analyzor

    @analyzor.setter
    def analyzor(self, value):
        self._analyzor = value

    def check(func):
        def inner(self):
            if self.analyzor == None:
                raise AnalysisModuleError("Can not run analyzor when it is still NULL")
            try:
                ret = func(self)
            except Exception as e:
                self.logger.exception("[{}] Exception happens: {}".format(self.analyzor.NAME, e))
                self.main_logger.exception(
                    "Case {} caught exception in plugin {}: {}".format(self.case_hash, self.analyzor.NAME, e))
                tb = traceback.format_exc()
                self.main_logger.error(tb)
                raise PluginRuntimeError(
                    "Case {} caught exception in plugin {}: {}".format(self.case_hash, self.analyzor.NAME, e))
            return ret

        return inner

    @check
    def run(self):
        self.main_logger.info("Running {}".format(self.analyzor.NAME))
        self.update_console_routine(self.analyzor.NAME)
        ret = self.analyzor.run()
        self.analyzor.dump_results()
        self._set_plugin_status(ret)
        self.analyzor.cleanup()
        return ret


    @check
    def generate_report(self):
        self.main_logger.debug("Generating report from {}".format(self.analyzor.NAME))
        return self.analyzor.generate_report()

    @check
    def success(self):
        return self.analyzor.success()

    @check
    def check_stamp(self):
        """
        Bool: True if stamp found, otherwise return False
        """
        stamp = "FINISH_" + self.analyzor.NAME.upper()
        ret = self._check_stamp(stamp)
        if ret:
            self.main_logger.info("{} has finished".format(self.analyzor.NAME))
            self.analyzor.set_history_status()
        return ret

    @check
    def create_stamp(self):
        stamp = "FINISH_" + self.analyzor.NAME.upper()
        self.main_logger.info("Finish {}".format(self.analyzor.NAME))
        return self._create_stamp(stamp)

    def null_results(self):
        plugin = self.cfg.get_plugin(self.analyzor.NAME)
        if plugin == None:
            return False
        plugin.instance.results = None
        plugin.instance.finish = False

    def plugin_finished(self, plugin_name):
        plugin = self.cfg.get_plugin(plugin_name)
        if plugin == None:
            return False
        return plugin.instance.finish

    def plugin_capable(self, plugin_name):
        return self.manager.module_capable(plugin_name)

    def cleanup(self):
        pass

    def dump_results(self):
        json.dump(self.results, open(os.path.join(self.syzkaller_path, "results.json"), 'w'))

    def build_mainline_kernel(self, commit=None, config=None, image=None, gcc_version=None, kernel=None, patch="",
                              keep_ori_config=False, extra_cmd="", kernel_repo="", branch="", config_enable=[],
                              config_disable=[]):
        self.set_stage_text("Building mainline kernel")
        if commit == None:
            commit = self.case["commit"]
        if config == None:
            config = self.case["config"]
        if image == None:
            image = "bullseye"
        if gcc_version == None:
            gcc_version = set_compiler_version(time_parser.parse(self.case["time"]), self.case["config"])

        if kernel == None:
            kernel = self.case["kernel"]
            try:
                if self.case["kernel"].startswith("https"):
                    kernel = self.case["kernel"].split('/')[-1].split('.')[0]
            except:
                pass
        if keep_ori_config:
            keep_ori_config = "1"
        else:
            keep_ori_config = "0"

        with open(os.path.join(self.path_case, 'enable_config'), 'w') as f:
            f.writelines(config_enable)
            if config_enable != []:
                f.write('\n')
            f.truncate()
        with open(os.path.join(self.path_case, 'disable_config'), 'w') as f:
            f.writelines(config_disable)
            if config_disable != []:
                f.write('\n')
            f.truncate()

        script = os.path.join(self.path_package, "scripts/deploy-linux.sh")
        chmodX(script)

        p = Popen([script, gcc_version, self.path_case, str(self.args.parallel_max), commit, config,
                   image, kernel_repo, "", str(self.index), kernel, patch, keep_ori_config, extra_cmd, branch],
                  stderr=STDOUT,
                  stdout=PIPE)
        with p.stdout:
            self._log_subprocess_output(p.stdout)
        exitcode = p.wait()
        self.info_msg("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode

    def err_msg(self, msg):
        self.logger.error(msg)

    def info_msg(self, msg):
        self.logger.info(msg)

    def debug_msg(self, msg):
        self.logger.debug(msg)

    def _get_analyzor_results_offline(self):
        plugin = self.cfg.get_plugin(self.analyzor.NAME)
        res = self._read_analyzor_results()
        if res == None:
            plugin.instance.finish = self._check_stamp("FINISH_" + self.analyzor.NAME.upper())
        else:
            plugin.instance.finish = self._check_stamp("FINISH_" + self.analyzor.NAME.upper())
            plugin.instance.results = res
        return

    def _set_plugin_status(self, ret):
        plugin = self.cfg.get_plugin(self.analyzor.NAME)
        plugin.instance.finish = ret

    def _read_analyzor_results(self):
        plugin_path = os.path.join(self.path_case, self.analyzor.NAME)
        results_path = os.path.join(plugin_path, "results.json")
        if not os.path.exists(results_path):
            return None
        try:
            res = json.load(open(results_path, 'r'))
        except:
            return None
        return res

    def _check_dependencies_finished(self):
        plugin = self.cfg.get_plugin(self.analyzor.NAME)
        dependencies = self.analyzor.DEPENDENCY_PLUGINS
        for plugin_name in dependencies:
            plugin = self.cfg.get_plugin(plugin_name)
            if plugin != None:
                if not plugin.instance.finish:
                    if plugin.dependency == "strong":
                        self.analyzor.logger.error(
                            "{} has a dependency {} not finished".format(self.analyzor.NAME, plugin_name))
                        return False
        return True

    def _build_plugin_folder(self):
        if os.path.exists(self.syzkaller_path):
            for i in range(1, 100):
                if not os.path.exists(self.syzkaller_path + "-{}".format(i)):
                    shutil.move(self.syzkaller_path, self.syzkaller_path + "-{}".format(i))
                    break
                if i == 99:
                    raise PluginFolderReachMaximumNumber(
                        "Plugin {} in {} reach the maximum number".format(self.analyzor.name, self.case_hash))
        os.makedirs(self.syzkaller_path, exist_ok=True)

    def _log_subprocess_output(self, pipe):
        for line in iter(pipe.readline, b''):
            self.logger.info(line)

    def _create_stamp(self, stamp):
        dst = "{}/.stamp/{}".format(self.path_case, stamp)
        call(['touch', dst])

    def _check_stamp(self, stamp):
        dst = "{}/.stamp/{}".format(self.path_case, stamp)
        return os.path.exists(dst)

    def _remove_stamp(self, stamp):
        dst = "{}/.stamp/{}".format(self.path_case, stamp)
        if os.path.exists(dst):
            os.remove(dst)

    def _init_module(self, module):
        if not isinstance(module, AnalysisModule):
            raise AnalysisModuleError("_init_module() requires class AnalysisModule")
        module.init(self.manager)
        module.setup()
        return module

    def _write_to(self, content, file):
        with open("{}".format(file), "w") as f:
            f.write(content)
            f.truncate()

    def _get_child_logger(self, logger):
        child_logger = logger.getChild(self.NAME)
        child_logger.propagate = self.debug
        child_logger.setLevel(logger.level)

        handler = logging.FileHandler("{}/log".format(self.syzkaller_path))
        format = logging.Formatter('[{}] %(asctime)s %(message)s'.format(self.NAME))
        handler.setFormatter(format)
        child_logger.addHandler(handler)
        return child_logger