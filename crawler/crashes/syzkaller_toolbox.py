import os
import csv
import glob
from utils import *
from subprocess import *


class SyzkallerInterface:

    def __init__(self, syzkaller_dir: str, config_path: str, repro_workdir: str):
        self.syzkaller_dir = syzkaller_dir
        self.syzkaller_commit = "c352ddf895e4f5a5b7e8f7caa37f476c6926326f"
        self.repro_workdir = repro_workdir
        self.config_path = config_path
        self.debug = True
        syz_logfile = os.path.join(self.repro_workdir, "syzkaller_log")
        open(syz_logfile, 'w')
        self.logger = init_logger(syz_logfile,
                                  cus_format='%(asctime)s %(message)s',
                                  debug=self.debug, propagate=self.debug)

    def patch_syzkaller(self, patch):
        p = Popen(["patch", "-p1", "-i", patch], cwd=self.syzkaller_dir, stdin=PIPE, stdout=PIPE)
        with p.stdout:
            log_anything(p.stdout, self.logger, self.debug)
        exitcode = p.wait()
        return exitcode

    # prepare for reproduction log
    def prepare_console_log(self, origin_log_path: str, suspicious_seqs: [str]) -> str:
        pass

    def run_syz_reproduce(self, console_log_path: str, raw_cover_dir: str):
        # -config=/home/weichen/deeptype/dynamic/kernel/fuzz_cfg/my.config
        # -coverfile=/home/weichen/StateRepro/data/repro_crashes/e3f8d4df1e1981a97abb/
        # /home/weichen/deeptype/dynamic/kernel/fuzz_cfg/workdir/crashes/b7e78ddc802d92f3419bfcf2ed9df69d09a6c317/log
        cmd = [os.path.join(self.syzkaller_dir, "syz-repro"),
               "-config", self.config_path,
               "-coverfile", raw_cover_dir,
               console_log_path]

    def run_syz_cover_symbolize(self, raw_cover_dir: str):
        # -config=/home/weichen/deeptype/dynamic/kernel/fuzz_cfg/my.config
        # -exports=rawcoverfiles
        # /home/weichen/StateRepro/data/repro_crashes/e3f8d4df1e1981a97abb/syzkaller1624505375_prog1.0
        cmd = [os.path.join(self.syzkaller_dir, "syz-cover"),
               "-config", self.config_path,
               "-exports", "rawcoverfiles"]

        unique_pcs = set()
        aggregate_file_path = os.path.join(raw_cover_dir, 'aggregate_cov')
        sym_files_pattern = os.path.join(raw_cover_dir, '**', '*.sym')
        for sym_file in glob.glob(sym_files_pattern, recursive=True):
            os.remove(sym_file)
        
        cov_files_pattern = os.path.join(raw_cover_dir, '**', f'*_prog*')
        cov_files = glob.glob(cov_files_pattern, recursive=True)
        for cov_file in cov_files:
            with open(cov_file, 'r') as file:
                unique_pcs.update(file.readlines())
        with open(aggregate_file_path, 'w') as file:
            file.writelines(unique_pcs)
        cmd.append(aggregate_file_path)

        local_command(' '.join(cmd), logger=self.logger, shell=True, cwd=raw_cover_dir)

        output_file = os.path.join(raw_cover_dir, 'rawcoverfiles')
        if not os.path.exists(os.path.join(raw_cover_dir, 'rawcoverfiles')):
            return None

        pc_to_info = {}
        with open(output_file, mode='r') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                pc_address = row['PC']
                info = {
                    'FuncName': row['FuncName'],
                    'Offset': row['Offset'],
                    'Filename': row['Filename'],
                    'Inline': row['Inline'],
                    'StartLine': row['StartLine'],
                    'EndLine': row['EndLine']
                }
                pc_to_info[pc_address] = info

        for cov_file in cov_files:
            sym_cov_file = cov_file + '.sym'
            write_file = open(sym_cov_file, 'w')
            with open(cov_file, 'r') as file:
                for pc in file.readlines():
                    pc = pc.strip()
                    if pc not in pc_to_info:
                        self.logger.info('fail to symbolize pc address {}'.format(pc))
                        continue
                    write_file.write(', '.join([pc, pc_to_info[pc]['FuncName'],
                                               pc_to_info[pc]['Filename'] + ':' + pc_to_info[pc]['StartLine']]) + '\n')
            write_file.close()

    def select_closest_sequence(self, suspicious_seqs: [str]):
        pass
