"""Two cleaner tests of the start-up cue (follow-up to startup_check.py). Offline.
  toolchain baseline : five flags (rseq, getrandom, set_robust_list, prlimit64, set_tid_address among the target
                       process's first 50 own calls), random forest, Table IV and Table V protocols
  start-up-only host : the 18 thesis host signals computed from only the first 50 own calls of every process
"""
import sys
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parent)); sys.path.insert(0, str(Path(__file__).resolve().parent / "evasion"))
import common as C, fasthost as FH, startup_check as S

rows, hc, nc = C.load(); y = C.labels(rows); g = C.groups_published(rows)
cats = np.asarray([r["category"] for r in rows])
gen = np.asarray([r["category"] in ("malware", "benign") for r in rows]); split = np.asarray([r["split"] for r in rows])
tr, te = np.flatnonzero(gen & (split == "train")), np.flatnonzero(gen & (split == "test"))
flags, startup_only = [], []
for i, r in enumerate(rows):
    w, p, s, root, pro = FH.load_events(i)
    abi = "i386" if r["mode"].startswith("i386") else "amd64"
    first = s[(p == root) & ~pro][:50]
    flags.append([float((first == n).any()) for n in S.STARTUP[abi].values()])
    own = np.flatnonzero(~pro)
    sp = p[own]; order = np.argsort(sp, kind="stable"); spo = sp[order]
    starts = np.r_[0, np.flatnonzero(spo[1:] != spo[:-1]) + 1] if len(spo) else np.zeros(0, int)
    rank = np.arange(len(spo)) - np.repeat(starts, np.diff(np.r_[starts, len(spo)])) if len(spo) else np.zeros(0, int)
    keep = np.zeros(len(w), bool); keep[own[order[rank < 50]]] = True
    startup_only.append(FH.to_columns(FH.host_windows(w[keep], p[keep], s[keep]), hc))
F, Hs, Xn = np.asarray(flags), np.asarray(startup_only), C.matrix(rows, nc)
out = {}
for name, X in (("toolchain_flags", F), ("host_startup_only", Hs)):
    P4 = C.fit_predict(X, Xn, y, g, tr, te, detectors=("host", "concat", "stacked"))
    PV, _ = C.cv_all(X, Xn, y, g, detectors=("host", "concat", "stacked"))
    out[name] = {d: {"table_iv_ba": round(C.metrics(y[te], P4[d])["balanced_accuracy"], 3),
                     "table_v_ba": round(float(np.mean([C.metrics(y, PV[d][s])["balanced_accuracy"] for s in range(10)])), 3),
                     "table_v_auc": round(float(np.mean([C.metrics(y, PV[d][s])["auc"] for s in range(10)])), 3),
                     "table_v_malware_recall": round(float((PV[d][:, cats == "malware"] >= .5).mean()), 3),
                     "table_v_benign_false_alarms": round(float((PV[d][:, cats == "benign"] >= .5).mean()), 3)}
                 for d in ("host", "concat", "stacked")}
    print(name, {d: (v["table_iv_ba"], v["table_v_ba"], v["table_v_auc"]) for d, v in out[name].items()})
C.write_json(C.HERE / "results" / "startup_check2.json", out)
