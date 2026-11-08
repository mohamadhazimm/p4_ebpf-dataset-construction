"""Targeted benign rebalance after the 2026-10-25 benign preflight dropped 5 dead amd64-static inetutils network cases.

Minimal churn: start from the pre-rebalance selection, remove exactly the 5 cases whose binary is in DROP_SHAS
(ftp a07b6ccf x2, ping c62a09ae x2, whois 28c65146 x1 -- all glibc-static, crashed/no-Sink), and backfill 5
amd64-static TRAINING compute cases (coreutils, an existing training project -> project-held-out preserved) using
programs NOT already selected, each with a benign_workloads spec, so they are guest-safe and host-preflightable.
Restores amd64-static benign to 59 (matching malware 59). The 100 kept cases are byte-identical to the validated
preflight set; only the 5 new cases need re-validation. No VM, no execution.
"""
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import benign_workloads as bw  # noqa: E402

STUDY = ROOT.parents[2]
BACKUP = STUDY / "data/benign/revision5-matched/benign_selection.before-rebalance-20261025.json"
INV = STUDY / "data/benign/revision5-matched/benign_inventory.json"
OUT = STUDY / "data/benign/revision5-matched/benign_selection.json"
DROP_SHAS = {"a07b6ccf421cfd89c7d5a61a594b2aafbf77e25177b50abe395f5a34afe0cc53",
             "c62a09ae3358f41bfc9cdafc8b6020b2a036ed9b4b039cf53967ae59ea6cf8a5",
             "28c651465cf9c78c843d58ca126e9422a9afaf3c872b83581799eb028e1c0324"}
SIZES = {"stream": {"light": 1, "medium": 16, "heavy": 64}}
# preferred new compute programs (distinct from those already selected), each with a benign_workloads spec, +bin
NEW = [("od", "light"), ("wc", "medium"), ("sort", "heavy"), ("sum", "light"), ("sha256sum", "medium")]


def main():
    sel = json.loads(BACKUP.read_text())
    inv = json.loads(INV.read_text())
    kept = [c for c in sel if c.get("sha256") not in DROP_SHAS]
    removed = len(sel) - len(kept)
    assert removed == 5, "expected to remove 5 dead cases, removed %d" % removed
    already = {(c["mode"], c["program"]) for c in kept if "program" in c}
    # index amd64_static coreutils compute binaries by program
    byprog = {}
    for r in inv:
        if r["mode"] == "amd64_static" and r["project"] == "coreutils":
            byprog.setdefault(r["program"], r)
    new_cases = []
    for program, abin in NEW:
        assert ("amd64_static", program) not in already, "program already selected: " + program
        bw.workload(program, abin)  # fail loudly if no guest-safe spec
        rec = byprog.get(program)
        assert rec, "no amd64_static coreutils build for " + program
        new_cases.append({"mode": "amd64_static", "split": "training", "project": "coreutils", "program": program,
                          "sha256": rec["sha256"], "source": rec["source"], "task_kind": "stream",
                          "activity_bin": abin, "fixture_size": SIZES["stream"][abin], "network": False,
                          "task_variant": abin})
    out = kept + new_cases
    # verification
    real = [c for c in out if "program" in c]
    assert len(real) == 105, "benign total != 105: %d" % len(real)
    amd = [c for c in real if c["mode"] == "amd64_static"]
    assert len(amd) == 59, "amd64_static benign != 59: %d" % len(amd)
    keys = Counter((c["mode"], c["split"], c["program"], c["sha256"], c["task_variant"]) for c in real)
    assert all(v == 1 for v in keys.values()), "duplicate case key: " + str([k for k, v in keys.items() if v > 1])
    tr = {c["project"] for c in real if c["split"] == "training"}
    va = {c["project"] for c in real if c["split"] == "validation"}
    assert not (tr & va), "project-held-out broken: " + str(sorted(tr & va))
    OUT.write_text(json.dumps(out, indent=1))
    print("removed 5 dead; added %d compute: %s" % (len(new_cases), [(c["program"], c["activity_bin"]) for c in new_cases]))
    for mode in ("amd64_static", "amd64_dynamic", "i386_static"):
        m = [c for c in real if c["mode"] == mode]
        print("  %-14s benign=%d network=%d" % (mode, len(m), sum(c["network"] for c in m)))
    print("  total network=%d / 105  | project-held-out OK" % sum(c["network"] for c in real))
    print("WROTE", OUT)


if __name__ == "__main__":
    main()
