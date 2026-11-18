"""Interim scoring of the sinkhole C2 runs finished so far (user request, 2026-11-13), while the collection runs.

Calls the frozen analyze_sinkhole_c2.py unchanged (its SHA is pinned in PREREGISTRATION_conn_features.json) and
writes to <attempt>/analysis/interim-<n>runs-<UTC>.json, never to results.json. Sink logs are not fetched yet, so
the Sink-log columns are empty here; detection uses only the host, switch and connection features.
The design stays frozen: nothing in the pre-registration may change because of these interim scores.

Run: nice -n 19 /usr/bin/python3 interim_score.py ATTEMPT_DIR
"""
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analyze_sinkhole_c2 as an  # noqa: E402

KEY_SETS = ("host", "network", "conn", "conn-no-first-contact", "network+conn", "hybrid", "hybrid+conn",
            "shape-hybrid", "shape-hybrid+conn", "stacked-hybrid", "stacked-hybrid+conn",
            "baseline-lifetime", "baseline-activity")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    attempt = Path(sys.argv[1]).resolve()
    host, net = an.tc.signals()
    _, rows = an.load_runs(attempt, host, net)
    catch, inetsim, dns = an.sink_logs(attempt)
    table = an.per_run_network(rows, host, net, catch, inetsim, dns, an.earlier_runs(net))
    scored = [r for r in rows if r["label"] in ("malware", "benign")]
    res = {"interim": True, "created_utc": datetime.now(timezone.utc).isoformat(), "attempt": str(attempt),
           "runs_loaded": len(rows), "by_label": dict(Counter(r["label"] for r in rows)),
           "groups": dict(Counter(r["group"] for r in scored)),
           "files_sha256": {"analyze_sinkhole_c2.py": sha(HERE / "analyze_sinkhole_c2.py"),
                            "conn_features.py": sha(HERE / "conn_features.py"),
                            "interim_score.py": sha(__file__),
                            "PREREGISTRATION_conn_features.json": sha(an.PREREG)}}
    res["detection_all"] = an.detection(scored, host, net)
    wire = [r for r, t in zip(rows, table) if r["label"] == "benign" or
            (r["label"] == "malware" and t["p4_packets_5min"] > 0)]
    if sum(1 for r in wire if r["label"] == "malware") >= 6:
        res["detection_wire_malware_only"] = an.detection(wire, host, net)
    out = attempt / "analysis"
    out.mkdir(exist_ok=True)
    path = out / ("interim-%druns-%s.json" % (len(rows), datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")))
    with open(path, "x") as f:
        json.dump(res, f, indent=2, default=str)
    print("runs", res["by_label"], "groups", res["groups"])
    for key in ("detection_all", "detection_wire_malware_only"):
        if key not in res:
            continue
        d = res[key]
        print("\n%s: %d malware / %d benign, %d groups" % (key, d["malware"], d["benign"], d["groups"]))
        for _, lab in an.PREFIXES:
            for s in KEY_SETS:
                v = d["scores"][lab + "|" + s]
                print("  %-5s %-22s BA %.3f +/- %.3f  AUC %.3f +/- %.3f" % (
                    lab, s, v["ba"]["mean"], v["ba"]["sd"], v["auc"]["mean"], v["auc"]["sd"]))
        for s in ("any|baseline-mode", "any|baseline-returncode"):
            v = d["scores"][s]
            print("  %-28s BA %.3f +/- %.3f  AUC %.3f" % (s, v["ba"]["mean"], v["ba"]["sd"], v["auc"]["mean"]))
        for name, c in d["comparisons"].items():
            print("  %-44s BA %+.3f +/- %.3f (higher in %d/10)  AUC %+.3f  -> %s" % (
                name, c["ba_diff"]["mean"], c["ba_diff"]["sd"], c["assignments_higher"], c["auc_diff"]["mean"],
                c["verdict"]))
    print("saved", path, sha(path))


if __name__ == "__main__":
    main()
