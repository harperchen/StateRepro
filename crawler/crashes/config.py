from reproducer.qemu.upstream import *


class Config:
    def __init__(self):
        self.upstream = None

    def load_from_file(self, config):
        work_path = os.getcwd()
        if not os.path.exists(config):
            config_path = os.path.join(work_path, config)
        else:
            config_path = config
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                cfg = json.load(f)
                f.close()
                return self.load(cfg)
        else:
            raise TargetFileNotExist(config)

    def load(self, cfg):
        kernel_cfg = cfg['kernel']
        self.upstream = Vendor(kernel_cfg["Upstream"])
        return cfg

    def get_all_kernels(self) -> List[Vendor]:
        res = [self.upstream]
        return res
