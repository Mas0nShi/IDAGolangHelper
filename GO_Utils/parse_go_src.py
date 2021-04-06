import os
import re
import json
import sys


def get_comments(index, lines):
    threshold = 20
    comment = ""
    for cc in range(1, threshold):
        line = lines[index - cc]
        if line.startswith("//"):
            comment += line
        else:
            return comment


def parse_go_lines(file_path):
    parsed = []
    with open(file_path, "r") as go_code:
        lines = go_code.readlines()
        for index, line in enumerate(lines):
            if line.startswith("func"):
                comment = get_comments(index, lines)
                offset = line.find("{")
                clean_up = line[:offset].rstrip()
                parsed.append((clean_up, comment))
    return parsed


def extract_func_name(func):
    tt = re.search(r"\s\w+\(", func)
    if tt:
        pp = tt.group(0)
        xx = pp.lstrip()[:-1]
        return xx
    return None


def extract_comments(file_path):
    temp = {}
    go_path = os.path.join(file_path, "src")
    for root, dirs, files in os.walk(go_path):
        for file in files:
            if "testdata" in root:
                break
            if file.endswith(".go"):
                if not file.endswith("_test.go"):
                    pp = os.path.join(root, file)
                    # get base name
                    func_matches = parse_go_lines(pp)
                    rm = "/src/"
                    rn = root[root.find(rm) + len(rm):]
                    if func_matches:

                        if rnGo not in temp:
                            temp[rn] = {}
                        for match in func_matches:
                            func_dec, comment = match
                            name = extract_func_name(func_dec)
                            if name in temp[rn]:
                                # skipping dups for now. TODO
                                continue
                            else:
                                temp[rn][name] = {"name": name, "func_dec": func_dec, "comment": comment, "file_name": file}
    return temp

def main():
    if len(sys.argv) < 2:
        print("ERROR: pass go source code root directory. Example 'python script.py repo/go'")
        return
    data = extract_comments(sys.argv[1])
    with open('gopher.json', 'w') as outfile:
        json.dump(data, outfile)
main()
