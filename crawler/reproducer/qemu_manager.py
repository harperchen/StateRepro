import socket

from reproducer.qemu.vm import VM
from utils import *

logger = logging.getLogger(__name__)

class QemuManager():
    def __init__(self, kernel_cfg, path_case):
        self.logger = logger
        self.kernel = kernel_cfg
        self.image_path = None
        self.vmlinux = None
        self.ssh_key = None
        self.distro_name = ""
        self.path_case = path_case
        self.path_linux = None
        self.index = 0
        self.root_user = None
        self.normal_user = None
        self._ssh_port = None
        self._mon_port = None
        self._gdb_port = None
        self._setup()

    def log(self, msg):
        if self.logger is not None:
            self.logger.info(msg)

    def init_logger(self, logger):
        self.logger = logger

    def prepare_img_bak(self, th_idx):
        path_image = os.path.join(self.path_case, "img")
        os.makedirs(path_image, exist_ok=True)
        if self.kernel.type == VM.DISTROS:
            self.create_snapshot(self.kernel.distro_image, path_image, th_idx, self.kernel.distro_name)
        if self.kernel.type == VM.UPSTREAM:
            self.create_snapshot(self.kernel.distro_image, path_image, th_idx, self.kernel.distro_name, target_format="raw")

    def _get_unused_port(self):
        so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        so.bind(('localhost', 0))
        _, port = so.getsockname()
        so.close()
        return port

    def _setup(self):
        self.normal_user = self.kernel.normal_user
        self.root_user = self.kernel.root_user
        self.vmtype = self.kernel.type
        self.ssh_port = self.kernel.ssh_port
        if self.kernel.gdb_port is not None:
            self.gdb_port = self.kernel.gdb_port
        if self.kernel.mon_port is not None:
            self.mon_port = self.kernel.mon_port
        if self.vmtype == VM.UPSTREAM:
            self.image_path = "{}/img/{}-snapshot.img".format(self.path_case, self.kernel.distro_name)
            self.vmlinux = "/home/weichen/StateRepro/crawler/qemu/vmlinux_kasan"
            self.ssh_key = self.kernel.ssh_key
            self.path_linux = "{}/linux-{}".format(self.path_case, self.kernel.distro_name)
            self.distro_name = self.kernel.distro_name

    def create_snapshot(self, src, img_dir, image_name, th_idx, target_format="qcow2"):
        dst = "{}/{}-snapshot{}.img".format(img_dir, image_name, str(th_idx))
        self.log("Create image {} from {}".format(dst, src))
        if os.path.isfile(dst):
            os.remove(dst)
        cmd = ["qemu-img", "create", "-f", "qcow2", "-b", src, "-F", target_format, dst]
        p = Popen(cmd, stderr=STDOUT, stdout=PIPE)
        exitcode = p.wait()
        return exitcode

    def _symlink(self, src, dst):
        if os.path.islink(dst):
            os.remove(dst)
        os.symlink(src, dst)

    @property
    def ssh_port(self):
        if self._ssh_port is None:
            return self._get_unused_port()
        return self._ssh_port

    @ssh_port.setter
    def ssh_port(self, port):
        self._ssh_port = port

    @property
    def mon_port(self):
        if self._mon_port is None:
            return self._get_unused_port()
        return self._mon_port

    @mon_port.setter
    def mon_port(self, port):
        self._mon_port = port

    @property
    def gdb_port(self):
        if self._gdb_port is None:
            return self._get_unused_port()
        return self._gdb_port

    @gdb_port.setter
    def gdb_port(self, port):
        self._gdb_port = port