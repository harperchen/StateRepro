kernel_func_to_syscall = {
    "write": ["write", "syz_emit_ethernet"],
    "writev": ["writev", "syz_emit_ethernet"],
    "nbd_genl_connect": ["sendmsg$NBD_CMD_CONNECT"],
    "nbd_genl_disconnect": ["sendmsg$NBD_CMD_DISCONNECT"],
    "nbd_genl_reconfigure": ["sendmsg$NBD_CMD_RECONFIGURE"],
    "nbd_genl_status": ["sendmsg$NBD_CMD_STATUS"],
}



def parse_call_trace_from_syscall(call_trace):
    """
    given a call trace, find the related syscall that trigger the crash
    """
    for line in reversed(call_trace.split('\n')):
        line = line.strip()
        if line.startswith('SyS_'):
            crashed_syscall = line[4:line.find('+')]
            return crashed_syscall
        elif line.startswith('__x64_sys_'):
            crashed_syscall = line[10:line.find('+')]
            return crashed_syscall
        elif line.startswith('__do_sys_'):
            if '+' in line:
                crashed_syscall = line[9:line.find('+')]
            else:
                crashed_syscall = line[9:line.find(' ')]
            return crashed_syscall
        elif line.startswith('__sys_'):
            crashed_syscall = line[6:line.find('+')]
            return crashed_syscall
        elif line.startswith('__arm64_sys_'):
            crashed_syscall = line[12:line.find('+')]
            return crashed_syscall
        elif line.startswith('__arm64_compat_sys_'):
            crashed_syscall = line[19: line.find('+')]
            return crashed_syscall
        elif line.startswith('ksys_'):
            if '+' in line:
                crashed_syscall = line[5:line.find('+')]
            else:
                crashed_syscall = line[5:line.find(' ')]
            return crashed_syscall
    return ""