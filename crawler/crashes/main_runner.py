import argparse

from reproducer.raw_reproducer import RawBugReproduce
from reproducer.minimize_feature import FeatureConfig
from crashes.crash_case import *
from crashes.poc_resolver import *

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--proj', nargs='?', action='store',
                        help='project name')
    parser.add_argument('--case', nargs='?', action='store',
                        help='case hash (If only run one case of the project')
    parser.add_argument('--config', nargs='?', action='store',
                        help='config file. Will be overwritten by arguments if conflict.')

    parser.add_argument('--timeout', nargs='?', action='store',
                        default='300', help='timeout when reproducing bug')
    parser.add_argument('--attempt', nargs='?', action='store',
                        default='3', help='attempt when reproducing bug')

    args = parser.parse_args()
    case = Case(args=args, index=0, work_dir="/home/weichen/StateRepro/data/repro_crashes/",
                case_dir='/home/weichen/StateRepro/data/local_crashes/warning_in_dtv5100_i2c_xfer')
    poc_resolver = PoCResolver()
    poc_resolver.extract_suspicious_seq([case.report])
    for execute_seq in case.report.executed_seqs.split('\n\n'):
        print(execute_seq)
        print()

    # poc_resolver.guess_if_stateful_static([report])
    testcases_dir = os.path.join(case.work_dir, "testcases")
    repro_testcases = case.report.prepare_repro_testcases(testcases_dir)

    feature = FeatureConfig(timeout=args.timeout, repro_attempt=args.attempt)
    raw_bug_reproduce = RawBugReproduce(feature, case=case)
    raw_bug_reproduce.run()
    case.symbolize_cover()

