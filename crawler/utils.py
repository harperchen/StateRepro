from typing import List


def parse_sysprog(syz_prog: str) -> str:
    syscall_names = []
    for line in syz_prog.split('\n'):
        if line.startswith('#'):
            continue
        idx1 = line.find('(')
        idx2 = line.find('=')
        if idx1 != -1:
            if idx2 != -1 and idx2 < idx1:
                name = line[idx2 + 2: idx1]
            else:
                name = line[:idx1]
            syscall_names.append(name)
    return '-'.join(syscall_names)

def is_sub_array(array1: List[str], array2: List[str]):
    i = 0  # Pointer for array1
    j = 0  # Pointer for array2

    while i < len(array1) and j < len(array2):
        if array1[i].startswith(array2[j]):
            i += 1
        j += 1

    return i == len(array1)  # Return True if all elements of array1 were found in array2
