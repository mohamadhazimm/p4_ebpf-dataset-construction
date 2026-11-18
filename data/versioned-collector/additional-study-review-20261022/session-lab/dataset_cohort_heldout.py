#!/usr/bin/env python3
"""The dataset's own programs re-collected in the session lab, scored on the paper's held-out split (Table IV).

Every program of the dataset cohort has exactly one accepted session under the main settings (the main run plus the
rest of the main plan). This takes those sessions' program rows from the base dataset (build_base.py: relaxed rule,
"sessions" view, the injected program's own windows from its injection), keeps the dataset's 99 malware and 105
benign tasks, gives each the paper's split (malware by SHA-256 from the release's features.csv; benign tasks by the
split their revision5 archive names carry, checked against the release's projects), and trains and tests the paper's
four detectors as the committee check did for Table IV (committee-eval common.fit_predict: RF500 balanced; stacked
late fusion over inner grouped folds; threshold 0.5; forest seeds 42 and 0-9). Same programs and split as Table IV,
different collection (busy background, hidden monitors, capture on the Sink, the passive sinkhole).

Network caveat: the sinkhole's silent listener is a lab cue in the session lab (session_lab.md section 7.3). The test
malware are split by whether they met a silent server in their first 20 s (silent_server_rows.csv, the rule that
counts only connections on which the program sent data), and the cue alone is scored as a rule on the same split.

Baselines on the same split (RF500 seed 42 on one input): activity (log total host system calls), lifetime (windows
with any host call), injection time, and mode.

The protocol is written to <out>/protocol.json before any score. Read-only on the run folders; nothing is executed.

  /usr/bin/python3 dataset_cohort_heldout.py --base base/20261117 --out <dir> [--dry-run]
"""
import argparse
import csv
import datetime
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ASR = HERE.parent
sys.path.insert(0, str(ASR / "committee-eval-20261113"))
import common as C   # noqa: E402

RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
RIGOR = ASR / "committee-eval-20261113" / "results" / "rigor.json"
RUNS = ("main", "rest")
RF_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
SPANS = ("20s", "80s")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_rows(base, span, release):
    """Program rows of the dataset cohort with the paper's split; checks the mapping against the release."""
    rows = [r for r in csv.DictReader((base / ("base_relaxed_sessions_%s.csv" % span)).open())
            if r["run"] in RUNS and r["kind"] in ("malware", "benign")]
    rel_mal = {r["sha256"]: r for r in release if r["category"] == "malware"}
    rel_ben = [r for r in release if r["category"] == "benign"]
    out, outside = [], []
    for r in rows:
        if r["kind"] == "malware":
            if r["sha256"] not in rel_mal:
                outside.append(r["name"])          # the 6 samples the dataset rejected
                continue
            r = dict(r, split=rel_mal[r["sha256"]]["split"])
        else:
            m = re.search(r"-(training|validation)-", r["archive"])
            r = dict(r, split={"training": "train", "validation": "test"}[m.group(1)])
        out.append(r)
    # the benign tasks' split must be the release's: same projects on each side, same counts
    for side in ("train", "test"):
        ses = sorted({r["project"] for r in out if r["kind"] == "benign" and r["split"] == side})
        rel = sorted({r["project"] for r in rel_ben if r["split"] == side})
        assert ses == rel, (side, ses, rel)
        assert sum(1 for r in out if r["kind"] == "benign" and r["split"] == side) == \
            sum(1 for r in rel_ben if r["split"] == side), side
    # malware: the session group is the release's family
    for r in out:
        if r["kind"] == "malware":
            assert r["group"].split("::")[-1] == rel_mal[r["sha256"]]["cv_group"].split("::")[-1].lower(), r["name"]
    missing = sorted(rel_mal[s]["family"] + "-" + s[:8] + " (" + rel_mal[s]["split"] + ")"
                     for s in set(rel_mal) - {r["sha256"] for r in out if r["kind"] == "malware"})
    return out, sorted(outside), missing


def cue_flags(base, rows):
    path = base / "silent-server" / "silent_server_rows.csv"
    cue = {(r["run"], r["sid"]): int(r["tcp_silent_server_client_sent"]) > 0 for r in csv.DictReader(path.open())}
    flags = [cue.get((r["run"], r["sid"])) for r in rows]
    assert all(f is not None for f in flags), "rows without a silent-server record"
    return np.asarray(flags, dtype=bool), sha256(path)


def baseline_inputs(rows):
    modes = sorted({r["mode"] for r in rows})
    return {"activity": np.log1p(np.asarray([[float(r["host_total_syscalls_total__sum"])] for r in rows])),
            "lifetime": np.asarray([[float(r["host_total_syscalls_total__active_windows"])] for r in rows]),
            "injection_time": np.asarray([[float(r["t_inject_s"])] for r in rows]),
            "mode": np.asarray([[float(r["mode"] == m) for m in modes] for r in rows])}


def summary(values):
    v = np.asarray(values, dtype=float)
    return {"mean": round(float(v.mean()), 3), "sd": round(float(v.std(ddof=1)), 3),
            "min": round(float(v.min()), 3), "max": round(float(v.max()), 3)}


def score_span(rows, cue):
    host = [c for c in rows[0] if c.startswith("host_")]
    net = [c for c in rows[0] if c.startswith("net_")]
    assert len(host) == 90 and len(net) == 145, (len(host), len(net))
    Xh = np.asarray([[float(r[c]) for c in host] for r in rows])
    Xn = np.asarray([[float(r[c]) for c in net] for r in rows])
    y = np.asarray([int(r["label"]) for r in rows])
    g = np.asarray([r["group"] for r in rows])
    tr = np.asarray([i for i, r in enumerate(rows) if r["split"] == "train"])
    te = np.asarray([i for i, r in enumerate(rows) if r["split"] == "test"])
    assert not set(g[tr]) & set(g[te]), "a group on both sides"
    yt = y[te]
    probs = {s: C.fit_predict(Xh, Xn, y, g, tr, te, rf_seed=s) for s in RF_SEEDS}
    rf42 = {d: C.metrics(yt, p) for d, p in probs[42].items()}
    res = {"n": {"train_malware": int(y[tr].sum()), "train_benign": int((y[tr] == 0).sum()),
                 "test_malware": int(yt.sum()), "test_benign": int((yt == 0).sum()),
                 "test_groups": len(set(g[te]))},
           "rf42": {d: {k: (round(v, 4) if isinstance(v, float) else v) for k, v in m.items()} for d, m in rf42.items()},
           "rf_seed_robustness": {d: {"balanced_accuracy": summary([C.metrics(yt, probs[s][d])["balanced_accuracy"]
                                                                    for s in RF_SEEDS]),
                                      "auc": summary([C.metrics(yt, probs[s][d])["auc"] for s in RF_SEEDS])}
                                  for d in C.DETECTORS}}
    # flag rates over the 11 forest seeds: per test family / project, and the test malware by the silent-server cue
    flagged = {d: np.mean([probs[s][d] >= 0.5 for s in RF_SEEDS], axis=0) for d in C.DETECTORS}
    rows_te = [rows[i] for i in te]
    cue_te = cue[te]
    by = defaultdict(list)
    for j, r in enumerate(rows_te):
        key = ("family::" + r["family"]) if r["kind"] == "malware" else ("project::" + r["project"])
        by[key].append(j)
    res["flag_rate_by_test_group"] = {k: {"n": len(v), **{d: round(float(flagged[d][v].mean()), 3)
                                                          for d in C.DETECTORS}} for k, v in sorted(by.items())}
    cells = {"malware_cue": [j for j in range(len(te)) if yt[j] == 1 and cue_te[j]],
             "malware_no_cue": [j for j in range(len(te)) if yt[j] == 1 and not cue_te[j]],
             "benign_cue": [j for j in range(len(te)) if yt[j] == 0 and cue_te[j]],
             "benign_no_cue": [j for j in range(len(te)) if yt[j] == 0 and not cue_te[j]]}
    res["flag_rate_by_cue"] = {k: {"n": len(v), **({d: round(float(flagged[d][v].mean()), 3) for d in C.DETECTORS}
                                                   if v else {})} for k, v in cells.items()}
    tp, fn = int(((cue_te) & (yt == 1)).sum()), int(((~cue_te) & (yt == 1)).sum())
    tn, fp = int(((~cue_te) & (yt == 0)).sum()), int(((cue_te) & (yt == 0)).sum())
    res["cue_rule"] = {"rule": "flag the program if it met a silent server in its first 20 s",
                       "balanced_accuracy": round((tp / (tp + fn) + tn / (tn + fp)) / 2, 3),
                       "tp": tp, "fn": fn, "tn": tn, "fp": fp}
    net_tp = [j for j in range(len(te)) if yt[j] == 1 and probs[42]["network"][j] >= 0.5]
    res["network_true_positives_rf42_with_cue"] = "%d/%d" % (sum(1 for j in net_tp if cue_te[j]), len(net_tp))
    b = baseline_inputs(rows)
    res["baselines_rf42_balanced_accuracy"] = {
        k: round(C.metrics(yt, C.rf(42).fit(v[tr], y[tr]).predict_proba(v[te])[:, 1])["balanced_accuracy"], 3)
        for k, v in b.items()}
    return res


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", default="base/20261117")
    p.add_argument("--out", required=True)
    p.add_argument("--dry-run", action="store_true", help="check the mapping only, no fitting")
    p.add_argument("--spans", default=",".join(SPANS))
    a = p.parse_args()
    base = (HERE / a.base) if not Path(a.base).is_absolute() else Path(a.base)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    release = list(csv.DictReader(RELEASE.open()))
    proto = out / "protocol.json"
    if not proto.exists():
        proto.write_text(json.dumps({
            "written_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "question": "the dataset's own programs, re-collected in sessions: scores on the paper's held-out split",
            "rows": "base dataset program rows (relaxed rule, sessions view) of the main run and the rest of the main plan",
            "split": "Table IV: malware by SHA-256 from the release features.csv; benign by the revision5 archive split",
            "detectors": "committee-eval common.fit_predict (host, network, concat, stacked), threshold 0.5",
            "rf_seeds": RF_SEEDS, "spans": list(SPANS),
            "network_caveat": "test malware split by the silent-server cue; the cue scored as a rule on the same split",
            "seen_before_writing": ["the interim per-program grouped CV of the main run's dataset programs (74 rows)",
                                    "the interim base (4 runs) grouped-CV scores", "the paper's Table IV",
                                    "nothing on this split with session rows"],
            "reading": "descriptive comparison with Table IV; no threshold or detector chosen on these scores",
            "script_sha256": sha256(__file__),
        }, indent=1))
    result = {"protocol_sha256": sha256(proto), "script_sha256": sha256(__file__),
              "table_iv_reference": json.loads(RIGOR.read_text())["A_table_iv"], "spans": {}}
    for span in [x for x in a.spans.split(",") if x]:
        csv_path = base / ("base_relaxed_sessions_%s.csv" % span)
        rows, outside, missing = load_rows(base, span, release)
        info = {"csv": str(csv_path.relative_to(HERE)), "csv_sha256": sha256(csv_path), "rows": len(rows),
                "outside_the_99": outside, "dataset_malware_without_a_row": missing}
        if a.dry_run:
            info["split_counts"] = {"%s_%s" % (k, s): sum(1 for r in rows if r["kind"] == k and r["split"] == s)
                                    for k in ("malware", "benign") for s in ("train", "test")}
        else:
            cue, cue_sha = cue_flags(base, rows)
            info["silent_server_rows_sha256"] = cue_sha
            info.update(score_span(rows, cue))
        result["spans"][span] = info
        print(span, json.dumps({k: v for k, v in info.items() if k in ("rows", "split_counts", "n", "outside_the_99",
                                                                      "dataset_malware_without_a_row")}))
    if not a.dry_run:
        (out / "heldout.json").write_text(json.dumps(result, indent=1))
        lines = []
        for span, info in result["spans"].items():
            lines.append("== %s: train %d malware / %d benign, test %d / %d (%d groups)" % (
                span, info["n"]["train_malware"], info["n"]["train_benign"], info["n"]["test_malware"],
                info["n"]["test_benign"], info["n"]["test_groups"]))
            for d in C.DETECTORS:
                m, rs = info["rf42"][d], info["rf_seed_robustness"][d]
                lines.append("  %-8s rf42 BA %.3f AUC %.3f  %d/%d/%d/%d   11 seeds BA %.3f +/- %.3f" % (
                    d, m["balanced_accuracy"], m["auc"], m["tn"], m["fp"], m["fn"], m["tp"],
                    rs["balanced_accuracy"]["mean"], rs["balanced_accuracy"]["sd"]))
            lines.append("  cue rule %s; network TPs with the cue %s; flag rate by cue %s" % (
                info["cue_rule"], info["network_true_positives_rf42_with_cue"], info["flag_rate_by_cue"]))
            lines.append("  baselines %s" % info["baselines_rf42_balanced_accuracy"])
        (out / "heldout.txt").write_text("\n".join(lines) + "\n")
        print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
