"""Repeated grouped CV of the combined-surface scoring (score_balanced_21.py), offline.

Runs score_balanced_21.main() unchanged except for the OUTER fold seed, over a seed list fixed
before any repeated result was seen: 42 (the paper's) and 0-8. Inner (meta-learner) folds keep
seed 7 and the Random Forest keeps its own fixed seed, so only the outer fold assignment varies.
Pool construction is computed once and reused. Writes repeated_cv.json next to this script.
Usage: repeat_cv.py <score_balanced_21.py> <realtools-attempt> <diverse-attempt>
"""
import json, sys, statistics, functools
from pathlib import Path

SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
orig, rt, dv = sys.argv[1:4]
here = Path(__file__).resolve().parent
src = open(orig).read()
a1 = "StratifiedGroupKFold(5, shuffle=True, random_state=42)"
assert src.count(a1) == 1
src = src.replace(a1, "StratifiedGroupKFold(5, shuffle=True, random_state=OUTER_SEED)")
a2 = '    (rt / "adfa_score_balanced.json").write_text(json.dumps(out, indent=2))\n    print("\\nwrote", rt / "adfa_score_balanced.json")\n'
assert src.count(a2) == 1
src = src.replace(a2, '''
    from sklearn.metrics import roc_auc_score
    fold_of = {}
    for k, (tr_, te_) in enumerate(StratifiedGroupKFold(5, shuffle=True, random_state=OUTER_SEED).split(Xh, y, g)):
        for i in te_:
            fold_of[g[i]] = k
    out["auc"] = {m: round(float(roc_auc_score(y, oof[m])), 3) for m in oof}
    out["qilin_akira_same_fold"] = fold_of.get("malware_signature::Qilin") == fold_of.get("malware_signature::Akira")
    RESULTS.append({"seed": OUTER_SEED, **out})
''')
a3 = 'if __name__ == "__main__":\n    main()'
assert src.count(a3) == 1
src = src.replace(a3, "")
g = {"__name__": "repeat_cv", "__file__": orig, "RESULTS": [], "OUTER_SEED": None}
exec(compile(src, orig, "exec"), g)

base, sf = g["base"], g["sf"]
base.prepare = functools.lru_cache(maxsize=None)(base.prepare)
_cache = {}
def build_record(path, name, *args, _orig=sf.build_record):
    if name not in _cache:
        _cache[name] = _orig(path, name, *args)
    return _cache[name]
sf.build_record = build_record

sys.argv = [orig, rt, dv]
for s in SEEDS:
    g["OUTER_SEED"] = s
    print(f"##### outer seed {s}", flush=True)
    g["main"]()

R = g["RESULTS"]
def summ(vals):
    return {"mean": round(statistics.mean(vals), 3), "sd": round(statistics.stdev(vals), 3),
            "min": round(min(vals), 3), "max": round(max(vals), 3)}
summary = {}
for m in ("host", "p4", "hybrid"):
    summary[m] = {k: summ([r["models"][m][k] for r in R]) for k in
                  ("BA", "precision", "recall", "specificity", "f1", "recall_general_malware", "recall_flood")}
    summary[m]["auc"] = summ([r["auc"][m] for r in R])
summary["hybrid_minus_host_BA"] = summ([r["models"]["hybrid"]["BA"] - r["models"]["host"]["BA"] for r in R])
summary["hybrid_minus_p4_BA"] = summ([r["models"]["hybrid"]["BA"] - r["models"]["p4"]["BA"] for r in R])
summary["hybrid_best_BA_in_n_of_10"] = sum(r["models"]["hybrid"]["BA"] > max(r["models"]["host"]["BA"], r["models"]["p4"]["BA"]) for r in R)
summary["qilin_akira_same_fold_in_n_of_10"] = sum(r["qilin_akira_same_fold"] for r in R)
(here / "repeated_cv.json").write_text(json.dumps({"seeds": SEEDS, "summary": summary, "per_seed": R}, indent=2))
print(json.dumps(summary, indent=1))
