"""Final toolchain class per executable, from the static fingerprint and the recorded start-up (offline).

    /usr/bin/python3 toolchain/classes.py
"""
import collections
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def label(o, seq):
    s = " ".join(seq[:50])
    if o["class"] == "upx":
        return "upx"
    if o["class"] == "go":
        return "go"
    if o["class"].startswith("dynamic") or o["class"] == "rust" and o.get("interp"):
        return "dynamic-glibc-loader"
    if not seq:
        return "no-start-up-recorded"
    if o["class"] == "musl" or (o["class"] == "unknown-static" and seq[:2] in (["arch_prctl", "set_tid_address"],
                                                                                ["set_thread_area", "set_tid_address"])):
        return "musl"
    if o["class"] == "uclibc" or (o["class"] == "unknown-static" and seq[:2] == ["ioctl", "ioctl"]):
        return "uclibc"
    if o["class"] == "unknown-static" and seq[0] == "rt_sigprocmask":
        return "uclibc"  # Mirai i386, GCC 4.1.2 cross-compiler, no libc start-up calls at all
    if "rseq" in s:
        return "glibc-static>=2.35"
    if "set_robust_list" in s or "set_tid_address" in s:
        return "glibc-static<2.35"
    return "other"


def main():
    fp = json.loads((HERE / "static_fingerprint.json").read_text())
    seqs = {o["row"]: o["first40"] for o in json.loads((HERE / "startup_sequences.json").read_text())}
    out = []
    for o in fp:
        lab = label(o, seqs.get(o["row"], []))
        out.append({k: o.get(k) for k in ("row", "category", "mode", "family", "project", "program", "go_version",
                                          "comment", "size")} | {"toolchain": lab, "startup12": seqs.get(o["row"], [])[:12]})
    (HERE / "toolchain_classes.json").write_text(json.dumps(out, indent=1))
    c = collections.Counter((o["category"], o["mode"], o["toolchain"]) for o in out)
    for k in sorted(c):
        print("%-8s %-14s %-22s %3d" % (k[0], k[1], k[2], c[k]))
    fam = collections.defaultdict(collections.Counter)
    for o in out:
        if o["category"] == "malware":
            fam[o["toolchain"]][o["family"]] += 1
    for t, f in sorted(fam.items()):
        print(t, dict(f))


if __name__ == "__main__":
    main()
