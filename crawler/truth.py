"""
A heuristic way to search for callees of indirect call in kernel

For instance, search for lines starting from .vidioc_querybuf could
give me an approximate solution of the callees for indirect call
vidioc_querybuf, e.g.,

.vidioc_querybuf = vb2_ioctl_querybuf,

python3 truth.py /home/weichen/linux_v6.2 vidioc_querybuf
"""

import re
import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def find_enclosing_structure_type(content, structure_type, field_name):
    lines = content.splitlines()

    property_pattern = re.compile(rf'^\s*\.{field_name}\s*=\s*(\S+)', re.MULTILINE)
    struct_start_pattern = re.compile(r'struct\s+(\w+)\s+(\w+)\s*=\s*\{')
    property_matches = [m for m in property_pattern.finditer(content)]

    for prop_match in property_matches:
        line_number = content[:prop_match.start()].count('\n')
        matched_field = lines[line_number].strip()

        for i in range(line_number, -1, -1):
            matches = struct_start_pattern.findall(lines[i])
            if matches:
                if matches[0][0] == structure_type:
                    return matched_field.replace('\t', '').replace(' ', '').replace('=', ' = ').replace(',', '')
                else:
                    return None
    return None


def search_callees(directory, struct_type, field_name):
    callees = set()
    path = Path(directory)

    for file in path.rglob('*'):
        if file.is_file() and file.suffix in ('.c', '.h'):
            with file.open('r') as f:
                contents = f.read()
                found_line = find_enclosing_structure_type(contents, struct_type, field_name)
                if found_line is None:
                    continue
                parts = found_line.split('=')
                if len(parts) == 2:
                    function_name = parts[1].strip()
                    logging.info(f"{file}: {found_line}")
                    callees.add(function_name)

    print(callees)


def find_functions_with_case(file_path, case_label):
    enclosed_funcs = set()
    function_pattern = r'\b(\w+\s+)+(\w+)\s*\(([^)]*)\)\s*\{'
    brace_pattern = r'{|}'
    case_pattern = r'\bcase\s+' + re.escape(case_label) + ':'

    function_stack = []
    current_function = None

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            combined_pattern = re.compile(f"({function_pattern})|({brace_pattern})|({case_pattern})")

            for match in combined_pattern.finditer(content):
                match_text = match.group(0)
                if re.match(function_pattern, match_text):
                    function_name = re.search(r'(\w+)\s*\(', match_text).group(1)
                    function_stack.append((function_name, match.start()))
                    current_function = function_name
                elif match_text == '{':
                    function_stack.append('{')
                elif match_text == '}':
                    if function_stack and function_stack[-1] == '{':
                        function_stack.pop()
                    else:
                        while function_stack and function_stack[-1] != '{':
                            current_function = function_stack.pop()[0]
                        if function_stack:
                            function_stack.pop()  # Remove the last '{'
                elif re.match(case_pattern, match_text) and function_stack:
                    print(f"Found case '{case_label}' in function {current_function} in file {file_path}")
                    enclosed_funcs.add(current_function)
                    break
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return enclosed_funcs


def search_cases(start_directory, case_label):
    enclosed_funcs = set()
    start_path = Path(start_directory)
    for file_path in start_path.rglob('*'):
        if file_path.is_file() and file_path.suffix in {'.c', '.h'}:
            enclosed_funcs.update(find_functions_with_case(file_path, case_label))
    print(enclosed_funcs)


if __name__ == '__main__':
    if sys.argv[1] == 'search-callee':
        if len(sys.argv) != 5:
            print("Usage: python script.py search-callee <directory> <struct_type> <field_name>")
            sys.exit(1)

        directory = sys.argv[2]
        struct_type = sys.argv[3]
        field_name = sys.argv[4]
        search_callees(directory, struct_type, field_name)
    elif sys.argv[1] == 'search-case':
        if len(sys.argv) != 4:
            print("Usage: python script.py search-case <directory> <case_label>")
            sys.exit(1)

        directory = sys.argv[2]
        case_label = sys.argv[3]
        search_cases(directory, case_label)
