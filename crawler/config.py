import os, json
import logging
import importlib

from errors import *
from qemu.vm import VM
from upstream import Vendor
from utils import *
from typing import List

base_ssh_port = 36777

logger = logging.getLogger(__name__)


class Config:
    def __init__(self):
        pass

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
        t = {}
        for vendor in kernel_cfg:
            vend_cfg = kernel_cfg[vendor]
            _cfg = Vendor(vend_cfg)
            if _cfg.distro_name not in t:
                setattr(self.kernel, vendor.lower(), _cfg)
                t[_cfg.distro_name] = True
            else:
                raise DuplicatedDistro(_cfg.distro_name)
        return cfg
