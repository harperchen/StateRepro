import argparse

from reproducer.raw_reproducer import RawBugReproduce
from reproducer.minimize_feature import SyzFeatureMinimize
from qemu.vm import VMInstance
from config import *
from case import *

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    parser.add_argument('--proj', nargs='?', action='store',
                        help='project name')
    parser.add_argument('--case', nargs='?', action='store',
                        help='case hash (If only run one case of the project')
    parser.add_argument('--config', nargs='?', action='store',
                        help='config file. Will be overwritten by arguments if conflict.')

    case = Case(args=args, index=0, proj_dir="fixed_crashes", case_hash="e3f8d4df1e1981a97abb")
    syzfeature_minimize = SyzFeatureMinimize(timeout=case.cfg["timeout"], repro_attempt=case.cfg["attempt"])
    raw_bug_reproduce = RawBugReproduce(syzfeature_minimize)
    raw_bug_reproduce.run()
