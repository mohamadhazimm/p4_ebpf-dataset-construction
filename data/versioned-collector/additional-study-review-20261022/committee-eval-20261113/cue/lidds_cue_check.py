"""Does LID-DS 2021 carry the lab cue of our dataset (connections nobody answers)? Offline, no fitting.

In our sealed lab only the Sink answers, so malware leaves TCP/UDP flows unanswered and benign programs do not
(cue/unanswered_cue.py). If LID-DS had the same giveaway, its network and hybrid results could rest on it too.
LID-DS packet captures were deleted after feature extraction, so the check uses the saved rows:

    U = net_flow_count_seen__sum - net_flows_with_ba__sum

summed over the 20 windows of a row; a window counts every active flow (seen in the last 3 windows) that has
not had a packet in the reverse direction so far (features/switch_model.py), so U > 0 when some window holds a
flow that nobody has answered yet. The proxy is first checked against the exact per-flow counts of our 240 rows
(cue/run_flows.csv). For LID-DS, attack windows are compared with normal windows: share of rows with U > 0,
the rule "flag a row with U > 0" (balanced accuracy), and the AUC of U and of U per flow as threshold-free
scores, next to the E2 detectors' per-scenario results (results.json of the 15-scenario evaluation).
Decided before computing: these definitions and outputs; only one LID-DS row had been looked at (an attack row
of CVE-2017-12635_6 with U = 5).

    nice -n 19 /usr/bin/python3 cue/lidds_cue_check.py
"""
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
EVAL = HERE.parent
REVIEW = EVAL.parent
LIDDS = REVIEW / "lidds-external" / "runs"
ROWS = [LIDDS / "20261105T213222Z" / "prepared" / "rows.json",
        LIDDS / "20261106T004530Z-batch2" / "prepared" / "rows.json"]
LIDDS_RESULTS = LIDDS / "20261106T004530Z-batch2" / "evaluation-20261106T011514Z" / "results.json"
RELEASE_CSV = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
RUN_FLOWS = HERE / "run_flows.csv"
OUT = EVAL / "results" / "lidds_cue_check.json"


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def auc(pos, neg):
    """Mann-Whitney AUC with average ranks for ties."""
    pos, neg = np.asarray(pos, float), np.asarray(neg, float)
    if not len(pos) or not len(neg):
        return None
    allv = np.r_[pos, neg]
    order = np.argsort(allv, kind="mergesort")
    ranks = np.empty(len(allv))
    sv = allv[order]
    i = 0
    while i < len(sv):
        j = i
        while j + 1 < len(sv) and sv[j + 1] == sv[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    rp = ranks[:len(pos)].sum()
    return float((rp - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def stats(rows):
    U = np.asarray([r["net_flow_count_seen__sum"] - r["net_flows_with_ba__sum"] for r in rows], float)
    F = np.asarray([r["net_flow_count_seen__sum"] for r in rows], float)
    ab = np.asarray([r["net_pkts_ab_delta__sum"] for r in rows], float)
    ba = np.asarray([r["net_pkts_ba_delta__sum"] for r in rows], float)
    return U, F, ab, ba


def describe(rows):
    U, F, ab, ba = stats(rows)
    n = len(rows)
    share = np.where(F > 0, U / np.maximum(F, 1), 0.0)
    return {"rows": n, "with_traffic": float((ab + ba > 0).mean()) if n else None,
            "with_unanswered": float((U > 0).mean()) if n else None,
            "no_reverse_packet_at_all": float(((ab > 0) & (ba == 0)).mean()) if n else None,
            "unanswered_median": float(np.median(U)) if n else None,
            "unanswered_share_of_flow_windows_median": float(np.median(share)) if n else None,
            "flow_windows_median": float(np.median(F)) if n else None}, U, F, share


def compare(att, nor):
    da, Ua, Fa, Sa = describe(att)
    dn, Un, Fn, Sn = describe(nor)
    rec, fa = da["with_unanswered"], dn["with_unanswered"]
    return {"attack": da, "normal": dn,
            "rule_flag_unanswered": {"recall": rec, "false_alarm": fa, "balanced_accuracy": (rec + 1 - fa) / 2},
            "auc_unanswered_count": auc(Ua, Un), "auc_unanswered_share": auc(Sa, Sn),
            "auc_flow_windows_reference": auc(Fa, Fn)}


def check_proxy():
    rel = {r["execution_id"]: r for r in csv.DictReader(open(RELEASE_CSV))}
    flows = list(csv.DictReader(open(RUN_FLOWS)))
    assert len(rel) == 240 and len(flows) == 240
    conf = {"both": 0, "proxy_only": 0, "exact_only": 0, "neither": 0}
    misses = []
    for f in flows:
        r = rel[f["execution_id"]]
        u = float(r["net_flow_count_seen__sum"]) - float(r["net_flows_with_ba__sum"])
        exact = int(f["unanswered_flows"]) > 0
        key = ("both" if u > 0 else "exact_only") if exact else ("proxy_only" if u > 0 else "neither")
        conf[key] += 1
        if key in ("proxy_only", "exact_only"):
            misses.append({"execution_id": f["execution_id"][:16], "category": f["category"], "proxy_U": u,
                           "exact_unanswered_flows": int(f["unanswered_flows"]), "flows": int(f["flows"])})
    return {"rows": 240, "confusion": conf, "disagreements": misses}


def main():
    proxy = check_proxy()
    rows = []
    for p in ROWS:
        rows.extend(json.load(open(p)))
    rows = [r for r in rows if r.get("error") is None]
    kinds = {k: sum(r["kind"] == k for r in rows) for k in ("attack", "normal", "end_control")}
    assert kinds == {"attack": 1721, "normal": 15305, "end_control": 15305}, kinds
    det = json.load(open(LIDDS_RESULTS))["E2_pooled_5fold"]
    out = {"proxy_check_on_our_240_rows": proxy, "lidds_rows": kinds,
           "pooled": compare([r for r in rows if r["kind"] == "attack"], [r for r in rows if r["kind"] == "normal"]),
           "end_control": describe([r for r in rows if r["kind"] == "end_control"])[0],
           "per_scenario": {}}
    for sc in sorted({r["scenario"] for r in rows}):
        att = [r for r in rows if r["scenario"] == sc and r["kind"] == "attack"]
        nor = [r for r in rows if r["scenario"] == sc and r["kind"] == "normal"]
        c = compare(att, nor)
        c["e2_detectors_balanced_accuracy"] = {m: det["per_scenario"][sc][m]["balanced_accuracy"]
                                              for m in ("host-only", "network-only", "hybrid", "concatenated")}
        out["per_scenario"][sc] = c
    out["e2_detectors_pooled_balanced_accuracy"] = {m: det["pooled"][m]["balanced_accuracy"]
                                                   for m in ("host-only", "network-only", "hybrid", "concatenated")}
    out["inputs_sha256"] = {str(p.relative_to(REVIEW)): sha(p) for p in ROWS + [LIDDS_RESULTS, RUN_FLOWS]}
    out["inputs_sha256"]["release:dataset/features.csv"] = sha(RELEASE_CSV)
    OUT.write_text(json.dumps(out, indent=1) + "\n")

    print("proxy vs exact on our 240 rows:", proxy["confusion"])
    for m in proxy["disagreements"]:
        print("   ", m)
    p = out["pooled"]
    print("LID-DS pooled: attack with unanswered %.3f, normal %.3f, end-control %.3f; rule BA %.3f; AUC U %.3f,"
          " AUC U/flow %.3f (flow-windows AUC %.3f)" % (
              p["attack"]["with_unanswered"], p["normal"]["with_unanswered"], out["end_control"]["with_unanswered"],
              p["rule_flag_unanswered"]["balanced_accuracy"], p["auc_unanswered_count"], p["auc_unanswered_share"],
              p["auc_flow_windows_reference"]))
    print("no reverse packet at all: attack %.4f normal %.4f" % (p["attack"]["no_reverse_packet_at_all"],
                                                              p["normal"]["no_reverse_packet_at_all"]))
    print("%-24s %7s %7s %7s %7s %7s | %6s %6s %6s %6s" % ("scenario", "att_U>0", "nor_U>0", "ruleBA", "aucU",
                                                         "aucShr", "host", "net", "hyb", "concat"))
    for sc, c in out["per_scenario"].items():
        d = c["e2_detectors_balanced_accuracy"]
        print("%-24s %7.3f %7.3f %7.3f %7.3f %7.3f | %6.3f %6.3f %6.3f %6.3f" % (
            sc[:24], c["attack"]["with_unanswered"], c["normal"]["with_unanswered"],
            c["rule_flag_unanswered"]["balanced_accuracy"], c["auc_unanswered_count"], c["auc_unanswered_share"],
            d["host-only"], d["network-only"], d["hybrid"], d["concatenated"]))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
