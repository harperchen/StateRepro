from crashes.report_local import *
from reproducer.qemu_executor import *
from reproducer.qemu.upstream import *

class Case:
    def __init__(self, args, index, case_dir: str, work_dir: str):
        self.index = index
        # source directory
        self.case_dir = case_dir
        
        if 'local' not in self.case_dir:
            self.report: KernelReport = self.read_case_syzbot()
        else:
            self.report: KernelReport = self.read_case_local()
        self.case_hash = self.report.report_hash
        self.work_dir = os.path.join(work_dir, self.case_hash)
        if os.path.exists(self.work_dir):
            import shutil
            shutil.rmtree(self.work_dir)
        os.makedirs(self.work_dir, exist_ok=True)
        self.syzkaller_toolbox = SyzkallerInterface(syzkaller_dir="/home/weichen/StateRepro/crawler/syzkaller",
                                                    config_path="/home/weichen/StateRepro/crawler/syzkaller/reproduce.cfg",
                                                    repro_workdir=self.work_dir)
        self.upstream = self.parse_vendor(args.config)
        self._init_case()

    
    # Parse a config file
    # Return a Config() object
    def parse_vendor(self, config):
        work_path = os.getcwd()
        if not os.path.exists(config):
            config_path = os.path.join(work_path, config)
        else:
            config_path = config
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                cfg = json.load(f)
                f.close()
                return Vendor(cfg['kernel']["Upstream"])
        else:
            raise TargetFileNotExist(config)

        return cfg

    def read_case_syzbot(self) -> KernelReport:
        cases_json_path = os.path.join(self.case_dir, 'console_data.json')
        if os.path.exists(cases_json_path):
            with open(cases_json_path, 'r') as f:
                case = json.load(f, cls=KernelReportDecoder)
                f.close()
        else:
            print("No proj {} found".format(cases_json_path))
            return None
        return case

    def read_case_local(self) -> KernelReport:
        report = KernelReport(kernel_commit='v6.2')
        with open(os.path.join(self.case_dir, 'hash'), 'r') as f:
            report.report_hash = f.read().strip()
        report.retrieve_report_local(os.path.join(self.case_dir, 'report'))
        report.retrieve_console_log_local(os.path.join(self.case_dir, 'log'))
        report.retrieve_call_trace()
        report.retrieve_executed_seqs()
        return report

    def _init_case(self):
        os.makedirs(self.work_dir, exist_ok=True)

        self.logger = init_logger(self.work_dir + "/log",
                                  cus_format='%(asctime)s %(message)s',
                                  debug=False, propagate=False)
        if len(self.case_hash) != 40:
            self.logger.info("https://syzkaller.appspot.com/bug?extid={}".format(self.case_hash))
        else:
            self.logger.info("https://syzkaller.appspot.com/bug?id={}".format(self.case_hash))

        
        self.upstream.executor = QemuExecutor(kernel_cfg=self.upstream, case_path=self.work_dir, logger=self.logger)

    def symbolize_cover(self):
        self.syzkaller_toolbox.run_syz_cover_symbolize(self.work_dir)