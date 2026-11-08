"""Matched-cohort BENIGN selection (offline; no VM, no execution here).

Assigns authenticated benign programs substantive, activity-tunable tasks so the benign activity distribution OVERLAPS
the malware's per mode (killing the 'more syscalls => malware' shortcut), hits the malware per-mode counts
(train 50/11/16, val 9/7/12 amd64-static/dyn/i386), keeps projects DISJOINT across the train/val split (global
project-held-out), caps programs per project, and makes ~1/3 of cases network-active to the internal Sink.
Each case gets an intended activity bin + fixture size from host calibration; the actual syscall count is measured and
bin-checked at host preflight (next step). Output is a selection plan, not a payload.
"""

import json, random, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
INV = STUDY / "data/benign/revision5-matched/benign_inventory.json"
OUT = STUDY / "data/benign/revision5-matched/benign_selection.json"
SEED = 42
PER_PROJECT_CAP = 6
TARGET = {"amd64_static": {"training": 50, "validation": 9},
          "amd64_dynamic": {"training": 11, "validation": 7},
          "i386_static": {"training": 16, "validation": 12}}
# intended activity-bin proportions per mode, shaped to overlap the .21 malware distribution (heavy-tailed)
BINS = {"amd64_static": [("light", .35), ("medium", .35), ("heavy", .30)],
        "amd64_dynamic": [("light", .20), ("medium", .40), ("heavy", .40)],
        "i386_static": [("light", .30), ("medium", .40), ("heavy", .30)]}
# fixture sizes per (task kind, bin): MB for streaming, files for tree, lines for sort, rows for sqlite
SIZES = {"stream": {"light": 1, "medium": 16, "heavy": 64},      # MB
         "tree":   {"light": 50, "medium": 500, "heavy": 2000},  # files
         "sort":   {"light": 10_000, "medium": 100_000, "heavy": 400_000},
         "sqlite": {"light": 2_000, "medium": 50_000, "heavy": 300_000},
         "net":    {"light": 1, "medium": 1, "heavy": 1}}
# program -> (task kind, tunable?, network?). Only activity-tunable / networking programs are eligible.
TASKS = {
    # hashing / crypto digests (stream)
    "sha256sum": ("stream", 1), "sha512sum": ("stream", 1), "b2sum": ("stream", 1), "sha1sum": ("stream", 1),
    "md5sum": ("stream", 1), "xxhsum": ("stream", 1), "sum": ("stream", 1), "cksum": ("stream", 1),
    # compression (stream)
    "gzip": ("stream", 1), "xz": ("stream", 1), "zstd": ("stream", 1), "lz4": ("stream", 1), "bzip2": ("stream", 1),
    "brotli": ("stream", 1), "compress": ("stream", 1), "xzdec": ("stream", 1),
    # sort/text (sort)
    "sort": ("sort", 1), "wc": ("stream", 1), "uniq": ("sort", 1), "od": ("stream", 1), "base32": ("stream", 1),
    "base64": ("stream", 1), "basenc": ("stream", 1),
    # archive / copy (tree)
    "tar": ("tree", 1), "cpio": ("tree", 1), "zip": ("tree", 1), "unzip": ("tree", 1), "rsync": ("tree", 1),
    # vcs
    "git": ("tree", 1),
    # db / parsers
    "sqlite3": ("sqlite", 1), "xmlwf": ("stream", 1), "diff": ("stream", 1), "cmp": ("stream", 1),
    "jq": ("stream", 1), "m4": ("stream", 1),
    # openssl digest (stream)
    "openssl": ("stream", 1),
    # NETWORK to Sink
    "curl": ("net", 1, True), "wget": ("net", 1, True), "ftp": ("net", 1, True), "ping": ("net", 1, True),
    "telnet": ("net", 1, True), "whois": ("net", 1, True),
}
NET = {"curl", "wget", "ftp", "ping", "telnet", "whois", "openssl"}  # openssl can be net (s_client) or local dgst
# Excluded after the 2026-10-25 benign preflight: these amd64-static inetutils builds are glibc-static and crash on
# the guest NSS path / reach no Sink traffic (ftp a07b6ccf, ping c62a09ae, whois 28c65146). The musl ftp/ping builds
# (b71bdfc4, 7fff972a) and telnet reach the Sink and are retained; the 5 freed slots backfill from other candidates.
DROP_SHAS = {"a07b6ccf421cfd89c7d5a61a594b2aafbf77e25177b50abe395f5a34afe0cc53",
             "c62a09ae3358f41bfc9cdafc8b6020b2a036ed9b4b039cf53967ae59ea6cf8a5",
             "28c651465cf9c78c843d58ca126e9422a9afaf3c872b83581799eb028e1c0324"}


def main():
    inv = json.loads(INV.read_text())
    # programs per (mode, project)
    avail = defaultdict(lambda: defaultdict(list))
    for r in inv:
        if r["program"] in TASKS and r["sha256"] not in DROP_SHAS:
            avail[r["mode"]][r["project"]].append(r)

    # Global project-held-out partition: a project is either train or val everywhere.
    all_projects = sorted({r["project"] for r in inv if r["program"] in TASKS})
    rng = random.Random(SEED)
    # Validation projects: reserve a diverse set (include some with heavy-capable + some network).
    VAL_PROJECTS = {"xz-utils", "libzstd", "unzip", "zip", "e2fsprogs", "ncurses", "net-tools", "bc",
                    "sharutils", "cpio", "brotli", "wget", "sqlite3", "diffutils", "expat", "m4"}
    split_of = {p: ("validation" if p in VAL_PROJECTS else "training") for p in all_projects}

    # several tasks per program: compute programs -> 3 activity bins; network programs -> 2 Sink tasks.
    BIG = {"coreutils", "util-linux", "inetutils"}
    # host preflight (2026-10-25) measured benign activity vs the .21 malware per-mode bands:
    # amd64_static benign already overlaps (med 543 vs malware 208), but i386_static (med 283 vs 1350)
    # and amd64_dynamic (med 720 vs 2769) sit below the malware median because the greedy selector
    # front-loads light bins. Emit heavy->medium->light for those two modes so the heavier tasks
    # (compress/b2sum heavy, git/jq/rsync heavy) are selected first and the benign median rises into
    # the malware range. amd64_static keeps light-first to retain its wide low-to-high spread.
    # Per-mode bin-pick order for the greedy selector. amd64_static has light-capable programs across the
    # spread, so light-first keeps its 24->32816 range. i386_static heavy-first still yields a full spread
    # because its "heavy" set includes naturally-light hashers (lz4/xxhsum). amd64_dynamic's programs
    # (git/rsync/jq/tar) are ALL syscall-heavy at the heavy fixture, so a pure heavy-first leaves no low-
    # activity cases to cover the malware 100-990 band; a heavy->light straddle picks both ends.
    BIN_ORDER = {"amd64_static": ("light", "medium", "heavy"),
                 "i386_static": ("heavy", "medium", "light"),
                 "amd64_dynamic": ("heavy", "light", "medium")}
    def program_cases(rec):
        prog, kind = rec["program"], TASKS[rec["program"]][0]
        if prog in NET:
            return [dict(rec, task_kind="net", activity_bin="net", task_variant=v,
                         fixture_size=1, network=True) for v in ("a", "b")]
        bins = BIN_ORDER.get(rec["mode"], ("light", "medium", "heavy"))
        return [dict(rec, task_kind=kind, activity_bin=b, task_variant=b,
                     fixture_size=SIZES.get(kind, SIZES["stream"])[b], network=False)
                for b in bins]

    selected = []
    for mode, needs in TARGET.items():
        for split, n in needs.items():
            projs = [p for p in avail[mode] if split_of.get(p) == split]
            rng.shuffle(projs)
            # candidate cases per project (sorted so output is deterministic)
            cand = {p: [c for rec in sorted(avail[mode][p], key=lambda r: r["program"])
                        for c in program_cases(rec)] for p in projs}
            want_net = max(1, round(n / 3))
            picks, per_proj = [], defaultdict(int)
            def cap(p): return 20 if p in BIG else 8
            # pass 1: satisfy the network quota first (round-robin net cases across projects)
            def take(pred):
                nonlocal picks
                progress = True
                while len(picks) < n and progress:
                    progress = False
                    for p in projs:
                        if len(picks) >= n: break
                        if per_proj[p] >= cap(p): continue
                        idx = next((i for i, c in enumerate(cand[p]) if pred(c)), None)
                        if idx is None: continue
                        picks.append(cand[p].pop(idx)); per_proj[p] += 1; progress = True
            take(lambda c: c["network"] and sum(x["network"] for x in picks) < want_net)
            take(lambda c: not c["network"])      # fill with compute cases
            take(lambda c: True)                   # top up with anything left (incl. extra net)
            for c in picks:
                c["split"] = split
                selected.append({k: c[k] for k in ("mode", "split", "project", "program", "sha256",
                                                    "source", "task_kind", "activity_bin", "fixture_size",
                                                    "network", "task_variant")})
            if len(picks) < n:
                selected.append({"mode": mode, "split": split, "SHORTFALL": n - len(picks),
                                 "available_projects": len(projs),
                                 "candidate_cases": sum(len(cand[p]) for p in projs) + len(picks)})

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(selected, indent=1))
    # report
    real = [c for c in selected if "program" in c]
    print(f"benign cases: {len(real)} (target {sum(sum(v.values()) for v in TARGET.values())})")
    for mode in TARGET:
        for split in ("training", "validation"):
            cs = [c for c in real if c["mode"] == mode and c["split"] == split]
            nets = sum(c["network"] for c in cs)
            projs = sorted({c["project"] for c in cs})
            print(f"  {mode:14s} {split:10s} n={len(cs):2d}/{TARGET[mode][split]:2d}  net={nets}  "
                  f"bins={dict((b, sum(c['activity_bin']==b for c in cs)) for b in ('light','medium','heavy','net'))}")
            print(f"      projects: {projs}")
    sf = [c for c in selected if "SHORTFALL" in c]
    if sf: print("SHORTFALLS:", sf)
    # project-held-out check
    tr = {c["project"] for c in real if c["split"]=="training"}; va = {c["project"] for c in real if c["split"]=="validation"}
    print("project-held-out OK:", not (tr & va), "| overlap:", sorted(tr & va))
    print("WROTE", OUT)


if __name__ == "__main__":
    main()
