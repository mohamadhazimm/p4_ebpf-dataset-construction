#!/usr/bin/env python3
"""The 240 dataset rows at the paper's 0.5 s x 40 windows without the launch prologue.

    /usr/bin/python3 build_05s.py OUTDIR

Redoes the 2026-11-04 launcher ablation with a script that stays here (the first run's scripts were
temporary). For each of the 240 rows of the release's dataset/features.csv it reads the run's
syscall_events.csv and exec_events.csv (run lookup and event parsing from ../switch-exact-1s/build_rows.py)
and recomputes the 90 host columns with the release's host_model.py:
  gate          with every call, the recomputed columns must equal the published row (relative 1e-9);
  prologuefree  without the root process's calls before its second exec success (the
                bash -c 'exec "$@"' -> target boundary; 178 calls in every run).
The 145 network columns and all metadata columns are copied from features.csv unchanged.
Outputs: features_05s_prologuefree.csv (features.csv layout), build.json (gate, prologue counts, the
launcher-signature features before and after, hashes).
"""
import csv
import glob
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "switch-exact-1s"))
import build_rows as br  # noqa: E402

hm, pc, REL = br.hm, br.pc, br.REL
SIGNATURE = ["host_first100_unique_mean__max", "host_max_run_length_max__max", "host_first50_unique_mean__max"]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader(open(REL / "dataset/features.csv", newline="")))
    pool = json.load(open(br.POOL))
    fields = list(rows[0])
    host_cols = [c for c in fields if c.startswith("host_")]
    assert len(host_cols) == 90
    rep = {"gate_host_max_rel": 0.0, "prologue_calls": {}, "signature": {}}
    sig = {(cat, v, f): [] for cat in ("malware", "benign") for v in ("with", "without") for f in SIGNATURE}
    free_rows = []
    for i, row in enumerate(rows):
        rj = glob.glob(str(br.run_dir(i, row, pool) / "output" / "run_*" / "run.json"))
        if len(rj) != 1:
            sys.exit("row %d: expected one run.json" % i)
        run = Path(rj[0]).parent
        meta = json.load(open(rj[0]))
        events, prologue = br.host_events(run, meta)
        full = pc.five(hm.window_features(events, windows=40), hm.FEATURES)
        free = pc.five(hm.window_features([e for e, m in zip(events, prologue) if not m], windows=40), hm.FEATURES)
        g = max(abs(full[c] - float(row[c])) / max(1.0, abs(float(row[c]))) for c in host_cols)
        rep["gate_host_max_rel"] = max(rep["gate_host_max_rel"], g)
        if g > 1e-9:
            sys.exit("row %d (%s): raw run does not reproduce the published host columns (%.2e)" % (i, row["execution_id"], g))
        n = sum(prologue)
        rep["prologue_calls"][n] = rep["prologue_calls"].get(n, 0) + 1
        if row["category"] in ("malware", "benign"):
            for f in SIGNATURE:
                sig[(row["category"], "with", f)].append(full[f])
                sig[(row["category"], "without", f)].append(free[f])
        r = dict(row)
        r.update(free)
        free_rows.append(r)
        print("[build] %3d %-60s prologue %d" % (i, row["execution_id"], n), flush=True)
    path = out / "features_05s_prologuefree.csv"
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for r in free_rows:
            w.writerow({k: (repr(v) if isinstance(v, float) else v) for k, v in r.items()})
    for (cat, v, f), vals in sig.items():
        rep["signature"]["%s|%s prologue|%s" % (cat, v, f)] = {"min": min(vals), "max": max(vals)}
    rep.update({"sha256_" + path.name: sha256(path), "features_csv_sha256": sha256(REL / "dataset/features.csv"),
                "host_model_sha256": sha256(REL / "features/host_model.py"),
                "build_rows_sha256": sha256(HERE.parent / "switch-exact-1s/build_rows.py"),
                "builder_sha256": sha256(Path(__file__))})
    json.dump(rep, open(out / "build.json", "w"), indent=1)
    print("[build] gate host %.1e; prologue calls per run %s" % (rep["gate_host_max_rel"], rep["prologue_calls"]))
    for k, v in rep["signature"].items():
        print("  %-70s %s" % (k, v))


if __name__ == "__main__":
    main()
