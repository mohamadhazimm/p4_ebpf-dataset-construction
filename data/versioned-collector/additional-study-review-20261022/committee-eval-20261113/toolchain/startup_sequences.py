"""Start-up call sequences of every execution (offline, from the recorded traces). Groups the target process's
first own calls (after the launcher prologue) into start-up patterns, per category and mode.

    /usr/bin/python3 toolchain/startup_sequences.py
"""
import collections
import json
import re
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent)); sys.path.insert(0, str(HERE.parent / "evasion"))
import common as C  # noqa: E402
import fasthost as FH  # noqa: E402


def table(path):
    t = {}
    for line in open(path):
        m = re.match(r"#define __NR_(\w+)\s+(\d+)", line)
        if m:
            t[int(m.group(2))] = m.group(1)
    return t


NAMES = {"amd64": table("/usr/include/x86_64-linux-gnu/asm/unistd_64.h"),
         "i386": table("/usr/include/x86_64-linux-gnu/asm/unistd_32.h")}


def startup(i, mode, n):
    w, p, s, root, pro = FH.load_events(i)
    own = s[(p == root) & ~pro][:n]
    abi = "i386" if mode.startswith("i386") else "amd64"
    return [NAMES[abi].get(int(x), str(int(x))) for x in own]


def main():
    rows, _, _ = C.load()
    out = []
    for i, r in enumerate(rows):
        if r["category"] not in ("malware", "benign"):
            continue
        seq = startup(i, r["mode"], 40)
        out.append({"row": i, "category": r["category"], "mode": r["mode"], "family": r["family"],
                    "project": r["project"], "program": r["program"], "sha256": r["sha256"], "first40": seq})
    (HERE / "startup_sequences.json").write_text(json.dumps(out, indent=1))
    # pattern = first 8 calls
    pat = collections.defaultdict(lambda: collections.Counter())
    for o in out:
        key = " ".join(o["first40"][:8])
        pat[(o["mode"], key)][o["category"] + ":" + (o["family"] or o["project"])] += 1
    for (mode, key), c in sorted(pat.items(), key=lambda kv: (kv[0][0], -sum(kv[1].values()))):
        mal = sum(v for k, v in c.items() if k.startswith("malware"))
        ben = sum(v for k, v in c.items() if k.startswith("benign"))
        print("%-14s mal %2d ben %2d | %s\n%s %s" % (mode, mal, ben, key, " " * 16, dict(c)))


if __name__ == "__main__":
    main()
