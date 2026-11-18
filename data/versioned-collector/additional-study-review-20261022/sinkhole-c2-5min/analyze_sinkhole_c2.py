"""Analysis of the sinkhole C2 experiment (offline; no VM, no merge, no model promotion).

  A  What reached the wire: per run, packets the switch features saw (first 20 s and 5 min), what the Sink logged
     (catch-all connections with the address each sample dialed, INetSim requests, DNS names), and for each
     malware sample the same sample's earlier 20-s run with the sinkhole off (viability probes of 2026-10-25).
  B  Detection, exploratory (56 runs): host = 18 ADFA signals x 5 statistics (90), network = 29 P4 signals x 5
     (145), hybrid = both (235); also the timing-free "shape" view pre-registered in the 5-minute study.
     Malware families and benign programs held out (StratifiedGroupKFold(5)), RF300 balanced, threshold 0.5,
     fold seeds 42 and 0-8, prefixes 20 s / 1 min / 5 min. Baselines: lifetime, activity, mode, return code.
     Also on the subset of malware that put packets on the wire.
  C  Added before any model was trained on these runs (PREREGISTRATION_conn_features.json): 30 payload-free
     connection-shape features (conn_features.py) alone, with the network block, and with both blocks; the
     stacked hybrid of the paper's Table V (release evaluation/combined.py, unchanged) with and without them;
     paired by fold assignment, with the decision rule fixed in the pre-registration.

Run: nice -n 19 /usr/bin/python3 analyze_sinkhole_c2.py ATTEMPT_DIR
"""
import csv
import glob
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from multiprocessing import Pool
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
PROJ = HERE.parent
sys.path.insert(0, str(PROJ / "host-gap-check-20261107"))
import compare_host as ch     # noqa: E402  summ(), job_cv(), SEEDS, summary()
import timing_control as tc   # noqa: E402  signals(), shape()
sys.path.insert(0, str(HERE))
import conn_features as cf    # noqa: E402  connection-shape features (pre-registered 2026-11-13)
sys.path.insert(0, ch.REL + "/evaluation")
import combined               # noqa: E402  release Table V stacked hybrid (unchanged)

PREREG = HERE / "PREREGISTRATION_conn_features.json"
PAIRS = (("network+conn", "network"), ("hybrid+conn", "hybrid"), ("shape-hybrid+conn", "shape-hybrid"),
         ("stacked-hybrid+conn", "stacked-hybrid"))
MIN_GAIN, MIN_ASSIGNMENTS = 0.02, 8      # decision rule, fixed in the pre-registration
EARLIER = [PROJ / "c2-viability/20261025T142642347649Z", PROJ / "evasive-viability/20261025T151638248361Z"]
PREFIXES = ((40, "20s"), (120, "1min"), (600, "5min"))
GUEST = "10.0.0.10"
MARGIN = timedelta(seconds=2)


def iso(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def load_runs(attempt, host, net):
    protocol = json.loads((attempt / "protocol.json").read_text())
    rows = []
    for case in protocol["cases"]:
        found = sorted((attempt / "runs" / case["sample"] / "output").glob("run_*/run.json"))
        if len(found) != 1:
            continue
        meta = json.loads(found[0].read_text())
        if meta.get("collection_quality_status") != "accepted":
            continue
        tel = list(csv.DictReader(open(found[0].with_name("telemetry.csv"))))
        if len(tel) != 600:
            continue
        if case["label"] != "null" and (meta.get("target_exec") or {}).get("status") != "observed":
            continue
        conn = cf.for_run(found[0].parent, [k / 2 for k, _ in PREFIXES])
        rows.append({"case": case, "meta": meta, "label": case["label"], "mode": case["mode"],
                     "C": {k: np.array(conn[k / 2]) for k, _ in PREFIXES},
                     "group": (case.get("family") and "fam:" + case["family"]) or
                              (case.get("program") and "prog:" + case["program"]) or "null",
                     "start": iso(tel[0]["window_start_utc"]), "end": iso(tel[-1]["window_end_utc"]),
                     "H": np.array([[float(t[s]) for s in host] for t in tel]),
                     "N": np.array([[float(t[s]) for s in net] for t in tel]),
                     "iface": np.array([float(t["net_packets_sent"]) + float(t["net_packets_recv"]) for t in tel])})
    return protocol, rows


def earlier_runs(net):
    """Per malware sample: P4 packets in the 40 windows of its earlier 20-s run (sinkhole off)."""
    out = {}
    pk = net.index("net_pkts_total_delta")
    for attempt in EARLIER:
        for rj in glob.glob(str(attempt / "runs/*/output/run_*/run.json")):
            sample = rj.split("/runs/")[1].split("/")[0]
            meta = json.load(open(rj))
            tel = list(csv.DictReader(open(rj.replace("run.json", "telemetry.csv"))))
            out[sample] = {"p4_packets": int(sum(float(t[net[pk]]) for t in tel)), "windows": len(tel),
                           "quality": meta.get("collection_quality_status"), "rc": meta.get("return_code")}
    return out


def sink_logs(attempt):
    sink = attempt / "sink"
    catch = []
    if (sink / "catchall.jsonl").exists():
        for line in (sink / "catchall.jsonl").read_text().splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("type") in ("tcp", "udp") and str(r.get("src", "")).startswith(GUEST + ":"):
                r["_t"] = iso(r.get("t_open") or r["t"])
                catch.append(r)
    inetsim = []
    pat = re.compile(r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\] \[\d+\] \[(\S+) \d+\] \[([\d.]+):(\d+)\] (.*)$")
    if (sink / "inetsim-service.log").exists():
        for line in (sink / "inetsim-service.log").read_text(errors="replace").splitlines():
            m = pat.match(line)
            if m and m.group(3) == GUEST:
                t = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                inetsim.append({"_t": t, "service": m.group(2), "port": int(m.group(4)), "text": m.group(5)})
    dns = []
    dpat = re.compile(r"^(\w{3} +\d+ \d\d:\d\d:\d\d) dnsmasq\[\d+\]: query\[(\w+)\] (\S+) from ([\d.]+)$")
    if (sink / "dnsmasq.log").exists():
        year = datetime.now(timezone.utc).year
        for line in (sink / "dnsmasq.log").read_text(errors="replace").splitlines():
            m = dpat.match(line)
            if m and m.group(4) == GUEST:
                t = datetime.strptime("%d %s" % (year, m.group(1)), "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
                dns.append({"_t": t, "type": m.group(2), "name": m.group(3)})
    return catch, inetsim, dns


def per_run_network(rows, host, net, catch, inetsim, dns, earlier):
    pk, hk = net.index("net_pkts_total_delta"), host.index("host_total_syscalls_total")
    table = []
    for r in rows:
        lo, hi = r["start"] - MARGIN, r["end"] + MARGIN
        c_tcp = [x for x in catch if x["type"] == "tcp" and lo <= x["_t"] <= hi]
        c_udp = [x for x in catch if x["type"] == "udp" and lo <= x["_t"] <= hi]
        ins = [x for x in inetsim if lo <= x["_t"] <= hi]
        names = [x["name"] for x in dns if lo <= x["_t"] <= hi]
        p4 = r["N"][:, pk]
        row = {"sample": r["case"]["sample"], "label": r["label"], "mode": r["mode"], "group": r["group"],
               "variant": r["case"].get("variant"), "rc": r["meta"].get("return_code"),
               "p4_packets_20s": int(p4[:40].sum()), "p4_packets_5min": int(p4.sum()),
               "p4_active_windows_5min": int((p4 != 0).sum()),
               "p4_last_active_window": int(np.nonzero(p4)[0].max()) if p4.any() else -1,
               "host_active_windows_5min": int((r["H"][:, hk] != 0).sum()),
               "catchall_tcp": len(c_tcp), "catchall_tcp_with_data": sum(1 for x in c_tcp if x.get("bytes_in")),
               "catchall_udp": len(c_udp),
               "catchall_destinations": sorted(Counter(x["orig_dst"] for x in c_tcp if x.get("orig_dst")).items()),
               "catchall_bytes_in": int(sum(x.get("bytes_in") or 0 for x in c_tcp + c_udp)),
               "inetsim_connections": sum(1 for x in ins if x["text"] == "connect"),
               "inetsim_requests": sum(1 for x in ins if x["text"].startswith("stat:")),
               "inetsim_services": sorted(Counter(x["service"] for x in ins if x["text"] == "connect").items()),
               "dns_queries": len(names), "dns_names": sorted(set(names))[:6]}
        if r["label"] == "malware":
            e = earlier.get(r["case"]["sample"])
            row["earlier_p4_packets_20s_sinkhole_off"] = e["p4_packets"] if e else None
        table.append(row)
    return table


def job_stacked(args):
    """The paper's Table V hybrid (release combined.run, unchanged): RF500 host and network models stacked by a
    class-balanced logistic regression on inner out-of-fold probabilities. Returns the hybrid's scores."""
    name, seed, Xh, Xn, y, g = args
    m = combined.run((seed, Xh, Xn, y, g))["hybrid"]
    return name, seed, {"ba": m["balanced_accuracy"], "auc": m["auc"], "tn": m["tn"], "fp": m["fp"],
                        "fn": m["fn"], "tp": m["tp"]}


def detection(rows, host, net):
    y = np.array([int(r["label"] == "malware") for r in rows])
    g = np.array([r["group"] for r in rows])
    h_gate, n_gate = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta")
    modes = sorted({r["mode"] for r in rows})
    sets, stacked = {}, []
    for k, lab in PREFIXES:
        Hf = np.array([ch.summ(r["H"], k) for r in rows])
        Nf = np.array([ch.summ(r["N"], k) for r in rows])
        Hs = np.array([tc.shape(r["H"], k, h_gate) for r in rows])
        Ns = np.array([tc.shape(r["N"], k, n_gate) for r in rows])
        sets[lab + "|host"] = Hf
        sets[lab + "|network"] = Nf
        sets[lab + "|hybrid"] = np.hstack([Hf, Nf])
        sets[lab + "|shape-hybrid"] = np.hstack([Hs, Ns])
        sets[lab + "|baseline-lifetime"] = Hf[:, [h_gate * 5 + 4]]
        sets[lab + "|baseline-activity"] = Hf[:, [h_gate * 5 + 2]]
        Cf = np.array([r["C"][k] for r in rows])
        sets[lab + "|conn"] = Cf
        sets[lab + "|conn-no-first-contact"] = Cf[:, cf.NO_FIRST_CONTACT]
        sets[lab + "|network+conn"] = np.hstack([Nf, Cf])
        sets[lab + "|hybrid+conn"] = np.hstack([Hf, Nf, Cf])
        sets[lab + "|shape-hybrid+conn"] = np.hstack([Hs, Ns, Cf])
        for s in ch.SEEDS:
            stacked.append((lab + "|stacked-hybrid", s, Hf, Nf, y, g))
            stacked.append((lab + "|stacked-hybrid+conn", s, Hf, np.hstack([Nf, Cf]), y, g))
    sets["any|baseline-mode"] = np.array([[float(r["mode"] == m) for m in modes] for r in rows])
    sets["any|baseline-returncode"] = np.array([[float(r["meta"].get("return_code") or 0)] for r in rows])
    jobs = [(name, X, y, g, s, 300) for name, X in sets.items() for s in ch.SEEDS]
    with Pool(8) as pool:
        out = pool.map(ch.job_cv, jobs)
        out_stacked = pool.map(job_stacked, stacked)
    per, oof = defaultdict(dict), defaultdict(list)
    for name, seed, sc, p in out:
        per[name][seed] = sc
        oof[name].append(p)
    for name, seed, sc in out_stacked:
        per[name][seed] = sc
    n_features = {name: int(X.shape[1]) for name, X in sets.items()}
    for name, _, Xh, Xn, _, _ in stacked:
        n_features[name] = int(Xh.shape[1] + Xn.shape[1])
    result = {}
    for name in per:
        vals = [per[name][s] for s in ch.SEEDS]
        result[name] = {"ba": ch.summary([v["ba"] for v in vals]), "auc": ch.summary([v["auc"] for v in vals]),
                        "n_features": n_features[name]}
        if oof.get(name):
            flagged = np.mean([p >= 0.5 for p in oof[name]], axis=0)
            result[name]["flag_rate_by_group"] = {grp: float(flagged[g == grp].mean()) for grp in sorted(set(g))}
    comparisons = {}
    for _, lab in PREFIXES:
        for a, b in PAIRS:
            d_ba = [per[lab + "|" + a][s]["ba"] - per[lab + "|" + b][s]["ba"] for s in ch.SEEDS]
            d_auc = [per[lab + "|" + a][s]["auc"] - per[lab + "|" + b][s]["auc"] for s in ch.SEEDS]
            higher = sum(1 for d in d_ba if d > 0)
            comparisons["%s|%s vs %s" % (lab, a, b)] = {
                "ba_diff": ch.summary(d_ba), "auc_diff": ch.summary(d_auc), "assignments_higher": higher,
                "verdict": "gain" if np.mean(d_ba) >= MIN_GAIN and higher >= MIN_ASSIGNMENTS else "no clear gain"}
    return {"n": len(y), "malware": int(y.sum()), "benign": int((y == 0).sum()), "groups": len(set(g)),
            "scores": result, "comparisons": comparisons}


def main():
    attempt = Path(sys.argv[1]).resolve()
    host, net = tc.signals()
    protocol, rows = load_runs(attempt, host, net)
    catch, inetsim, dns = sink_logs(attempt)
    earlier = earlier_runs(net)
    table = per_run_network(rows, host, net, catch, inetsim, dns, earlier)
    scored = [r for r in rows if r["label"] in ("malware", "benign")]
    res = {"attempt": str(attempt), "accepted_runs": len(rows),
           "accepted_by_label": dict(Counter(r["label"] for r in rows)), "per_run": table,
           "sink_records": {"catchall": len(catch), "inetsim_lines": len(inetsim), "dns_queries": len(dns)},
           "conn_feature_names": cf.NAMES, "decision_rule": {"min_mean_ba_gain": MIN_GAIN,
                                                             "min_assignments_higher": MIN_ASSIGNMENTS},
           "preregistration": {"file": str(PREREG), "sha256": hashlib.sha256(PREREG.read_bytes()).hexdigest()
                               if PREREG.exists() else None}}
    counts = Counter(r["label"] for r in scored)
    if min(counts.get("malware", 0), counts.get("benign", 0)) >= 5 and len({r["group"] for r in scored}) >= 5:
        res["detection_all"] = detection(scored, host, net)
    wire = [r for r, t in zip(rows, table) if r["label"] == "benign" or
            (r["label"] == "malware" and (t["p4_packets_5min"] > 0 or t["catchall_tcp"] or t["catchall_udp"]))]
    if sum(1 for r in wire if r["label"] == "malware") >= 6:
        res["detection_wire_malware_only"] = detection(wire, host, net)
    out = attempt / "analysis"
    out.mkdir(exist_ok=True)
    (out / "results.json").write_text(json.dumps(res, indent=2, default=str))
    print(json.dumps({"accepted": res["accepted_by_label"], "sink_records": res["sink_records"]}, indent=2))
    for t in table:
        print("%-7s %-16s %-24s rc=%-4s p4_20s=%-6s p4_5min=%-7s before=%-5s catch=%-3s(%s data) udp=%-3s inetsim=%-3s dns=%-3s %s"
              % (t["label"], t["group"][:16], (t["variant"] or t["sample"][:12])[:24], t["rc"], t["p4_packets_20s"],
                 t["p4_packets_5min"], t.get("earlier_p4_packets_20s_sinkhole_off", ""), t["catchall_tcp"],
                 t["catchall_tcp_with_data"], t["catchall_udp"], t["inetsim_connections"], t["dns_queries"],
                 ",".join("%s x%d" % kv for kv in t["catchall_destinations"][:2])))
    for key in ("detection_all", "detection_wire_malware_only"):
        if key not in res:
            continue
        d = res[key]
        print("\n%s: %d malware / %d benign, %d groups" % (key, d["malware"], d["benign"], d["groups"]))
        for name, s in d["scores"].items():
            print("  %-28s BA %.3f +/- %.3f   AUC %.3f +/- %.3f" % (name, s["ba"]["mean"], s["ba"]["sd"],
                                                                  s["auc"]["mean"], s["auc"]["sd"]))
        for name, c in d["comparisons"].items():
            print("  %-44s BA %+.3f +/- %.3f (higher in %d/10)  AUC %+.3f  -> %s" % (
                name, c["ba_diff"]["mean"], c["ba_diff"]["sd"], c["assignments_higher"], c["auc_diff"]["mean"],
                c["verdict"]))
    print("saved", out / "results.json")


if __name__ == "__main__":
    main()
