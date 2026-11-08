#!/usr/bin/env python3
"""Step 1 of RUNBOOK 19.5.7 / 19.7.5 item 4: the 240 dataset rows at 1 s windows, with the switch's rules
on the network side and without the launch prologue on the host side.

    /usr/bin/python3 build_rows.py OUTDIR

For each of the 240 rows of the release's dataset/features.csv:
  gate   the run's raw data reproduce the row as published: the release switch_model.py at 0.5 s x 40
         gives the 145 network columns, and the release host_model.py on syscall_events.csv (with the
         launch prologue) gives the 90 host columns;
  build  four 1 s x 20 variants of the row, network {published, switch} x host {as collected, prologue-free}:
           network published = switch_model.py's rules at 1 s (TTL 3 windows);
           network switch    = the packager's SwitchRules (RUNBOOK 19.7.2's six rules, p4_ebpf
                               live_test/package_cohort.py) at 1 s;
           host as collected = the 0.5 s windows of syscall_events.csv paired into 1 s (window_id // 2);
           host prologue-free = the same without the root process's calls before its second
                               exec success (the bash -> target boundary; 178 calls per run, 19.5.6).
         and per run the 1 s windows of the main variant (switch, prologue-free) for step 3.

Outputs: features_1s_<net>_<host>.csv (features.csv layout, metadata columns unchanged),
windows_1s_switch_prologuefree.csv, build.json (gates, hashes, prologue counts).
"""
import csv
import glob
import hashlib
import json
import sys
from pathlib import Path

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022")
PACKAGER = Path("/home/ali/Desktop/Hazim/p4_ebpf/live_test")
REV5 = STUDY / "revision5-collection/20261025T100025568989Z"
POOL = STUDY / "paper-check-20261028/independent_pool.json"
RT = STUDY / "realtools-collect/20261026T165642798242Z"
DV = STUDY / "flood21-collect/20261026T154421063760Z"
X1 = STUDY / "flood21-collect/20261026T150016786262Z"
X2 = STUDY / "flood21-collect/20261026T151240756153Z"

sys.path.insert(0, str(PACKAGER))
import package_cohort as pc  # noqa: E402

release = pc.load_release(REL)
sm = release[0]
sys.path.insert(0, str(REL / "features"))
import host_model as hm  # noqa: E402


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_dir(i, row, pool):
    if i < 204:
        return REV5 / "runs" / pool[i]["sample"]
    name = row["execution_id"]
    if row["category"] == "network_attack":
        base = RT
    elif name in ("bulkdl", "nullidle"):
        base = X1
    elif name.startswith("bulk") and not name.startswith("bulkup"):
        base = X2
    else:
        base = DV
    return base / "runs" / (name + ".zip")


def host_events(run, meta):
    root = meta["sample_root_pid"]
    succ = [int(e["timestamp_ns"]) for e in csv.DictReader(open(run / "exec_events.csv"))
            if e["event"] == "exec_success" and int(e["pid"]) == root]
    cut = succ[1] if len(succ) >= 2 else None
    events, prologue = [], []
    for r in csv.DictReader(open(run / "syscall_events.csv")):
        if r["event"] != "syscall":
            continue
        try:
            sid = int(r["detail"].split("id=")[1].split()[0])
        except (IndexError, ValueError):
            continue
        events.append((int(r["window_id"]), int(r["pid"]), sid))
        prologue.append(cut is not None and int(r["pid"]) == root and int(r["timestamp_ns"]) < cut)
    return events, prologue


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader(open(REL / "dataset/features.csv", newline="")))
    pool = json.load(open(POOL))
    fields = list(rows[0])
    host_cols = [c for c in fields if c.startswith("host_")]
    net_cols = [c for c in fields if c.startswith("net_")]
    assert len(host_cols) == 90 and len(net_cols) == 145
    sw1 = pc.SwitchRules(release, 1.0, 20)
    pub1 = pc.SwitchRules(release, 1.0, 20, rules=())
    variants = {(n, h): [] for n in ("published", "switch") for h in ("ascollected", "prologuefree")}
    window_rows, report = [], {"gate_net_max_rel": 0.0, "gate_host_max_rel": 0.0, "prologue_calls": {}, "runs": {}}
    for i, row in enumerate(rows):
        run_base = run_dir(i, row, pool)
        rj = glob.glob(str(run_base / "output" / "run_*" / "run.json"))
        if len(rj) != 1:
            sys.exit("%s: expected one run.json" % run_base)
        run = Path(rj[0]).parent
        meta = json.load(open(rj[0]))
        anchor = int(meta["sample_started_wall_us"])
        pcap = run / "packet_capture.pcap"
        # gates: the raw data give the published row
        net05 = pc.five(sm.window_features(str(pcap), anchor, 0.5, 40), sm.FEATURES)
        events, prologue = host_events(run, meta)
        host05 = pc.five(hm.window_features(events, windows=40), hm.FEATURES)
        gn = max(abs(net05[c] - float(row[c])) / max(1.0, abs(float(row[c]))) for c in net_cols)
        gh = max(abs(host05[c] - float(row[c])) / max(1.0, abs(float(row[c]))) for c in host_cols)
        report["gate_net_max_rel"] = max(report["gate_net_max_rel"], gn)
        report["gate_host_max_rel"] = max(report["gate_host_max_rel"], gh)
        if gn > 1e-9 or gh > 1e-9:
            sys.exit("row %d (%s): the raw run does not reproduce the published row (net %.2e, host %.2e)"
                     % (i, row["execution_id"], gn, gh))
        n_pro = sum(prologue)
        report["prologue_calls"][n_pro] = report["prologue_calls"].get(n_pro, 0) + 1
        # 1 s variants
        _, records = pc.read_pcap(pcap)
        net_w = {"published": pub1.run(records, anchor), "switch": sw1.run(records, anchor)}
        e1 = [(w // 2, p, s) for (w, p, s) in events]
        e1_free = [(w // 2, p, s) for (w, p, s), m in zip(events, prologue) if not m]
        host_w = {"ascollected": hm.window_features(e1, windows=20), "prologuefree": hm.window_features(e1_free, windows=20)}
        for (n, h), lst in variants.items():
            r = dict(row)
            r.update(pc.five(net_w[n], sm.FEATURES))
            r.update(pc.five(host_w[h], hm.FEATURES))
            lst.append(r)
        for j in range(20):
            window_rows.append({"execution_id": row["execution_id"], "run_id": meta["run_id"], "window": j,
                                **{f: net_w["switch"][j][f] for f in sm.FEATURES},
                                **{f: host_w["prologuefree"][j][f] for f in hm.FEATURES}})
        report["runs"][row["execution_id"]] = {"run_dir": str(run), "run_id": meta["run_id"], "anchor_us": anchor,
                                              "prologue_calls": n_pro}
        print("[build] %3d %-66s prologue %d" % (i, row["execution_id"], n_pro), flush=True)
    for (n, h), lst in variants.items():
        path = out / ("features_1s_%s_%s.csv" % (n, h))
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
            w.writeheader()
            for r in lst:
                w.writerow({k: (repr(v) if isinstance(v, float) else v) for k, v in r.items()})
        report["sha256_" + path.name] = sha256(path)
    path = out / "windows_1s_switch_prologuefree.csv"
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(window_rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(window_rows)
    report["sha256_" + path.name] = sha256(path)
    report.update({"features_csv_sha256": sha256(REL / "dataset/features.csv"),
                   "packager_sha256": sha256(PACKAGER / "package_cohort.py"),
                   "host_model_sha256": sha256(REL / "features/host_model.py"),
                   "switch_model_sha256": sha256(REL / "features/switch_model.py"),
                   "builder_sha256": sha256(Path(__file__))})
    json.dump(report, open(out / "build.json", "w"), indent=1)
    print("[build] gates: network %.1e, host %.1e; prologue calls per run %s"
          % (report["gate_net_max_rel"], report["gate_host_max_rel"], report["prologue_calls"]))


if __name__ == "__main__":
    main()
