"""Run a program under strace -f and print the names of the first N system calls of the main process after execve.
    /usr/bin/python3 -I first_calls.py N OUTFILE -- prog args...
"""
import re, subprocess, sys
n = int(sys.argv[1]); out = sys.argv[2]; argv = sys.argv[sys.argv.index("--") + 1:]
r = subprocess.run(["strace", "-f", "-o", out, "--", *argv], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
main_pid, seen, names = None, False, []
for line in open(out):
    m = re.match(r"^(\d+)\s+(?:<\.\.\. )?([a-z_0-9]+)[\( ]", line)
    if not m:
        continue
    pid, name = m.group(1), m.group(2)
    if main_pid is None:
        main_pid = pid
    if pid != main_pid:
        continue
    if "resumed>" in line and line.split()[1] == "<...":
        continue
    if not seen:
        if name == "execve" and "= 0" in line:
            seen = True
        continue
    names.append(name)
    if len(names) >= n:
        break
print("rc=%d %s" % (r.returncode, " ".join(names)))
