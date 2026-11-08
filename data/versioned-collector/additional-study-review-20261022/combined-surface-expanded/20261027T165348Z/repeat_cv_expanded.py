"""Option 1: expand the combined-surface benign pool with already-collected busy-but-benign
network workloads (bulk downloads + idle null), then repeat grouped CV over 10 fold seeds.
Offline re-scoring only; no VM; originals untouched. The extra benign are HARD negatives
(high-volume network, 2k-14k post-launch syscalls), so this makes the test harder, not easier.
Usage: repeat_cv_expanded.py <score_balanced_21.py> <realtools-attempt> <diverse-attempt>
"""
import json, sys, statistics, functools
from pathlib import Path
SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
orig, rt, dv = sys.argv[1:4]
src = open(orig).read()
src = src.replace("StratifiedGroupKFold(5, shuffle=True, random_state=42)",
                  "StratifiedGroupKFold(5, shuffle=True, random_state=OUTER_SEED)")
anchor = '    for n in NULLS:\n        add(dv, n, 0, "null", "null")\n'
assert src.count(anchor) == 1
inject = anchor + '''
    _xb = dv.parent
    EXTRA = [("20261026T150016786262Z", "bulkdl", "net_benign", "netb_bulkdl"),
             ("20261026T150016786262Z", "nullidle", "null", "null"),
             ("20261026T151240756153Z", "bulk400", "net_benign", "netb_bulkup"),
             ("20261026T151240756153Z", "bulk700", "net_benign", "netb_bulkup"),
             ("20261026T151240756153Z", "bulk1000", "net_benign", "netb_bulkup"),
             ("20261026T151240756153Z", "bulk1300", "net_benign", "netb_bulkup"),
             ("20261026T151240756153Z", "bulk1600", "net_benign", "netb_bulkup"),
             ("20261026T151240756153Z", "bulk2000", "net_benign", "netb_bulkup")]
    for _a, _n, _st, _g in EXTRA:
        add(_xb / _a, _n, 0, _st, _g)
'''
src = src.replace(anchor, inject)
a2 = '    (rt / "adfa_score_balanced.json").write_text(json.dumps(out, indent=2))\n    print("\\nwrote", rt / "adfa_score_balanced.json")\n'
assert src.count(a2) == 1
src = src.replace(a2, '''
    from sklearn.metrics import roc_auc_score
    out["auc"] = {m: round(float(roc_auc_score(y, oof[m])), 3) for m in oof}
    out["n_benign"] = int((y == 0).sum()); out["n"] = int(len(y))
    RESULTS.append({"seed": OUTER_SEED, **out})
''')
src = src.replace('if __name__ == "__main__":\n    main()', "")
g = {"__name__": "x", "__file__": orig, "RESULTS": [], "OUTER_SEED": None}
exec(compile(src, orig, "exec"), g)
base, sf = g["base"], g["sf"]
base.prepare = functools.lru_cache(maxsize=None)(base.prepare)
_cache = {}
def build_record(path, name, *a, _o=sf.build_record):
    if name not in _cache: _cache[name] = _o(path, name, *a)
    return _cache[name]
sf.build_record = build_record
sys.argv = [orig, rt, dv]
for s in SEEDS:
    g["OUTER_SEED"] = s; print("##### seed", s, flush=True); g["main"]()
R = g["RESULTS"]
def summ(v): return {"mean": round(statistics.mean(v), 3), "sd": round(statistics.stdev(v), 3),
                     "min": round(min(v), 3), "max": round(max(v), 3)}
S = {}
for m in ("host", "p4", "hybrid"):
    S[m] = {k: summ([r["models"][m][k] for r in R]) for k in ("BA", "precision", "recall", "specificity", "f1")}
    S[m]["auc"] = summ([r["auc"][m] for r in R])
S["hybrid_best_in_n_of_10"] = sum(r["models"]["hybrid"]["BA"] > max(r["models"]["host"]["BA"], r["models"]["p4"]["BA"]) for r in R)
S["pool"] = {"n": R[0]["n"], "n_benign": R[0]["n_benign"]}
Path(__file__).with_name("expanded_cv.json").write_text(json.dumps({"seeds": SEEDS, "summary": S, "per_seed": R}, indent=2))
print(json.dumps(S, indent=1))
