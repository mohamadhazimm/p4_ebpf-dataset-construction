#!/usr/bin/env python3
"""What the 99 malware samples of the first collection did during their 20-s observation, by malware type.

Offline, from saved files only (no VM, no model fit):
- release dataset/features.csv: family, return code, split;
- p4_ebpf collector/detector/dataset_windows.csv.gz: the 240 runs' 0.5-s window signals (host calls and packets per
  window; their 40-window summaries are the published rows, checked here for the call and packet sums);
- sample-intel-20261113/triage_network-20261115.csv: network behaviour of each sample on Triage's Internet-connected
  sandbox (2026-11-15 analysis);
- thesis data/lab/combined_cv.json: the Table V out-of-fold probabilities (10 fold assignments), for the recall of
  each detector by type at threshold 0.5.

Writes sample_behaviour.json (per type and per sample) next to this script and prints the table.
"""
import csv
import gzip
import hashlib
import json
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
WS = Path("/home/ali/Desktop/Hazim")
FEATURES = WS / "p4-ebpf-malware-detection/dataset/features.csv"
WINDOWS = WS / "p4_ebpf/collector/detector/dataset_windows.csv.gz"
TRIAGE = HERE.parent / "sample-intel-20261113/triage_network-20261115.csv"
CV = WS / "a-unified-p4-ebpf-architecture-for-host-and-network-malware-detection/data/lab/combined_cv.json"

TYPE = {}
for f in ("mirai gafgyt kaiji tsunami dofloo ddosagent kaiten chaos katana xorddos billgates chinaz rapperbot").split():
    TYPE[f] = "DDoS and IoT botnets"
for f in "akira qilin bert lockbit inc nitrogen promptlock noescape".split():
    TYPE[f] = "Ransomware"
for f in "brickstorm deskrat getshell ngioweb".split():
    TYPE[f] = "Backdoors, remote-access tools, proxies"
for f in "coinminer prometei".split():
    TYPE[f] = "Cryptominers"
TYPE["catstorm"] = "Type not established"
ORDER = ["DDoS and IoT botnets", "Ransomware", "Backdoors, remote-access tools, proxies", "Cryptominers",
         "Type not established"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    rows = [r for r in csv.DictReader(open(FEATURES)) if r["category"] == "malware"]
    assert len(rows) == 99, len(rows)
    by_id = {r["execution_id"]: r for r in rows}

    win = defaultdict(dict)
    with gzip.open(WINDOWS, "rt") as fh:
        for r in csv.DictReader(fh):
            if r["execution_id"] in by_id:
                win[r["execution_id"]][int(r["window"])] = (float(r["host_total_syscalls_total"]),
                                                           float(r["net_pkts_total_delta"]))
    assert len(win) == 99 and all(len(w) == 40 for w in win.values())

    triage = {r["sha256"]: r for r in csv.DictReader(open(TRIAGE))}
    cv = json.load(open(CV))
    seeds = [str(s) for s in cv["seeds"]]
    idx = {s: i for i, s in enumerate(cv["samples"])}

    per_sample = []
    for eid, r in by_id.items():
        w = win[eid]
        calls = [w[k][0] for k in range(40)]
        pkts = [w[k][1] for k in range(40)]
        # the 40-window sums are the published summaries
        assert abs(sum(calls) - float(r["host_total_syscalls_total__sum"])) < 1e-6, eid
        assert abs(sum(pkts) - float(r["net_pkts_total_delta__sum"])) < 1e-6, eid
        active = [k for k in range(40) if calls[k] > 0]
        rc = int(r["return_code"])
        if rc == 0:
            ending = "exit 0"
        elif rc == -15:
            ending = "running at 20 s"
        elif rc > 0:
            ending = "exit error"
        else:
            ending = "signal"
        t = triage[r["sha256"]]["triage_class"]
        i = idx[r["execution_id"] + ".zip"]   # the saved predictions name a malware run by its archive
        assert cv["labels"][i] == 1 and cv["strata"][i] == "general_malware", eid
        flags = {d: sum(cv["oof"][s][d][i] >= 0.5 for s in seeds) for d in ("host", "network", "hybrid")}
        per_sample.append({
            "execution_id": eid, "family": r["family"], "type": TYPE[r["family"].lower()], "split": r["split"],
            "return_code": rc, "ending": ending, "active_windows": len(active),
            "first_window_only": active == [0] or not active, "last_active_window": max(active) if active else -1,
            "active_last_5s": any(calls[k] > 0 for k in range(30, 40)), "packets": sum(pkts),
            "sent_packets": sum(pkts) > 0, "triage_class": t,
            "triage_network": t in ("all_answered", "some_unanswered", "none_answered"),
            "flags_of_10": flags,
        })

    def summary(items):
        n = len(items)
        return {
            "samples": n,
            "families": len({s["family"] for s in items}),
            "first_window_only": sum(s["first_window_only"] for s in items),
            "active_last_5s": sum(s["active_last_5s"] for s in items),
            "exit_0": sum(s["ending"] == "exit 0" for s in items),
            "exit_error": sum(s["ending"] == "exit error" for s in items),
            "signal": sum(s["ending"] == "signal" for s in items),
            "running_at_20s": sum(s["ending"] == "running at 20 s" for s in items),
            "sent_packets_lab": sum(s["sent_packets"] for s in items),
            "network_on_triage": sum(s["triage_network"] for s in items),
            "triage_uncertain": sum(s["triage_class"] == "uncertain" for s in items),
            "recall": {d: round(sum(s["flags_of_10"][d] for s in items) / (10 * n), 3)
                       for d in ("host", "network", "hybrid")},
        }

    out = {"by_type": {t: summary([s for s in per_sample if s["type"] == t]) for t in ORDER},
           "all": summary(per_sample),
           "per_sample": sorted(per_sample, key=lambda s: (ORDER.index(s["type"]), s["family"], s["execution_id"])),
           "sources": {str(p): sha(p) for p in (FEATURES, WINDOWS, TRIAGE, CV)},
           "notes": "first_window_only: host calls of the lineage only in window 0 (the window that holds the "
                    "launch); active_last_5s: any call in windows 30-39; ending from the root's return code "
                    "(-15 = still running when the collector ended the observation); network_on_triage: Triage "
                    "classes all/some/none answered (uncertain counted apart); recall: share of the 10 Table V "
                    "assignments x samples flagged at 0.5 (hybrid = stacked)."}
    (HERE / "sample_behaviour.json").write_text(json.dumps(out, indent=1))
    fmt = "%-42s %3s %4s %4s | %4s %4s %4s %4s | %4s %4s %3s | %5s %5s %5s"
    print(fmt % ("type", "n", "fam", "w0", "ex0", "err", "sig", "run", "last5", "pkts", "tri", "host", "net", "stk"))
    for t in ORDER + ["all"]:
        s = out["all"] if t == "all" else out["by_type"][t]
        print(fmt % (t[:42], s["samples"], s["families"], s["first_window_only"], s["exit_0"], s["exit_error"],
                     s["signal"], s["running_at_20s"], s["active_last_5s"], s["sent_packets_lab"],
                     s["network_on_triage"], s["recall"]["host"], s["recall"]["network"], s["recall"]["hybrid"]))


if __name__ == "__main__":
    main()
