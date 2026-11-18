"""Compare the host-recorded start-up of every rebuilt benign program with the start-up the analysis VM recorded for
the dataset's malware of the same toolchain class and mode (offline; reads only derived start-up name lists).

    /usr/bin/python3 -I scripts/startup_compare.py <benign-build dir> <host_check json> [<host_check json> ...]

Per benign build: the five start-up flags of the committee analysis (rseq, getrandom, set_robust_list, prlimit64,
set_tid_address among the first 50 own calls), the toolchain-specific start-up prefix (the calls before the
program's own work, see libc_prefix), and the best match against the malware sequences of the same class+mode:
longest common prefix in calls and a difflib similarity over the first 12 calls.
Note: host kernel 6.8 vs VM kernel 7.0; start-up calls are made by the C library / runtime, not by the kernel.
"""
import collections
import difflib
import json
import sys
from pathlib import Path

BB = Path(sys.argv[1]).resolve()
TC = BB.parent  # .../toolchain
FLAGS = ["rseq", "getrandom", "set_robust_list", "prlimit64", "set_tid_address"]
LIBC_CALLS = {"arch_prctl", "set_thread_area", "set_tid_address", "set_robust_list", "futex", "rt_sigaction",
              "rt_sigprocmask", "getrlimit", "ugetrlimit", "prlimit64", "uname", "readlink", "rseq", "getrandom",
              "brk", "_sysctl"}


def libc_prefix(cls, seq):
    """Calls issued by the libc/runtime start-up before the program's own work (empirical boundary per class)."""
    if cls == "uclibc":
        if seq[2:5] in (["getpid", "getrlimit", "setrlimit"], ["getpid", "ugetrlimit", "setrlimit"]):
            return seq[:12]  # ioctl x2 + linuxthreads manager set-up (pthread linked)
        return seq[:2]  # ioctl(TCGETS) on stdin and stdout from the stdio initialisation
    if cls == "go":
        return seq[:5]  # arch_prctl|set_thread_area, sched_getaffinity, open(at) THP size file, read, close
    if cls.startswith("glibc"):
        end = 0
        for i, c in enumerate(seq[:16]):
            if c not in LIBC_CALLS:
                break
            end = i + 1
        return seq[:end]
    if cls == "upx":
        for i, c in enumerate(seq[:30]):
            if c == "munmap":
                return seq[:i + 1]
        return seq[:12]
    if cls == "musl":
        return seq[:2]
    return seq[:12]


def lcp(a, b):
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def fv(seq):
    return "".join(str(int(f in seq)) for f in FLAGS)


def main():
    cls_rows = {o["row"]: o for o in json.loads((TC / "toolchain_classes.json").read_text())}
    mal = collections.defaultdict(list)
    for o in json.loads((TC / "startup_sequences.json").read_text()):
        c = cls_rows[o["row"]]
        if c["category"] == "malware" and c["mode"].endswith("static"):
            mal[(c["mode"], c["toolchain"])].append({"family": c["family"], "seq": o["first40"]})
    res = {}
    for f in sys.argv[2:]:
        for r in json.loads(Path(f).read_text())["results"]:
            res[(r["toolchain"], r["program"])] = r
    out = []
    summary = collections.defaultdict(lambda: {"n": 0, "flags": collections.Counter(), "prefix_match": 0, "lcp": []})
    for (tc, prog), r in sorted(res.items()):
        seq, cls, mode = r["startup50"], r["toolchain_class"], r["mode"]
        pre = libc_prefix(cls, seq)
        best = None
        for m in mal.get((mode, cls), []):
            mp = libc_prefix(cls, m["seq"])
            cand = {"family": m["family"], "malware_prefix": mp, "lcp": lcp(seq, m["seq"]), "prefix_equal": pre == mp,
                    "sim12": round(difflib.SequenceMatcher(None, seq[:12], m["seq"][:12]).ratio(), 3)}
            if best is None or (cand["prefix_equal"], cand["lcp"], cand["sim12"]) > (
                    best["prefix_equal"], best["lcp"], best["sim12"]):
                best = cand
        mal_fv = collections.Counter(fv(m["seq"]) for m in mal.get((mode, cls), []))
        rec = {"toolchain": tc, "program": prog, "class": cls, "mode": mode, "flags": fv(seq),
               "startup_prefix": pre, "best_malware_match": best,
               "flag_vector_seen_in_malware_of_class": mal_fv.get(fv(seq), 0) > 0}
        out.append(rec)
        s = summary[(mode, cls, tc)]
        s["n"] += 1
        s["flags"][fv(seq)] += 1
        s["prefix_match"] += int(bool(best and best["prefix_equal"]))
        s["lcp"].append(best["lcp"] if best else 0)
    malsum = {}
    for (mode, cls), v in mal.items():
        malsum["%s|%s" % (mode, cls)] = {
            "n": len(v), "flag_vectors": dict(collections.Counter(fv(m["seq"]) for m in v)),
            "prefixes": dict(collections.Counter(" ".join(libc_prefix(cls, m["seq"])) for m in v))}
    summ = {"%s|%s|%s" % k: {"n": v["n"], "flag_vectors": dict(v["flags"]),
                             "prefix_equal_to_a_malware_prefix": v["prefix_match"],
                             "median_lcp_with_best_malware": sorted(v["lcp"])[len(v["lcp"]) // 2] if v["lcp"] else 0}
            for k, v in summary.items()}
    (BB / "checks" / "startup_compare.json").write_text(json.dumps(
        {"flag_order": FLAGS, "malware_by_class": malsum, "benign_summary": summ, "benign": out}, indent=1))
    print("MALWARE (mode|class): n, flag vectors over (%s), libc/runtime start-up prefixes" % ",".join(FLAGS))
    for k, v in sorted(malsum.items()):
        print("  %-34s n=%-3d %s" % (k, v["n"], v["flag_vectors"]))
        for p, n in sorted(v["prefixes"].items(), key=lambda kv: -kv[1]):
            print("      %2d x %s" % (n, p))
    print("BENIGN builds (mode|class|toolchain): n, flag vectors, #prefix equal to a malware prefix, median LCP")
    for k, v in sorted(summ.items()):
        print("  %-62s n=%-3d %-28s prefix_eq=%-3d lcp=%d" % (k, v["n"], v["flag_vectors"],
                                                              v["prefix_equal_to_a_malware_prefix"],
                                                              v["median_lcp_with_best_malware"]))


if __name__ == "__main__":
    main()
