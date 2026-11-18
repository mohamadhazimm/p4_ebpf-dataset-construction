"""How would the network and hybrid scores change if the five Tsunami bots had not seen our collector? Offline estimate.

In the sensor-visibility test (../sensor-visibility/, step 1 B) the five held-out Tsunami bots connected within a
second when nothing of ours ran in the guest, while in the dataset they quit without traffic (step 2: because of
what they see running, not their own path). B recorded their traffic outside the guest (VirtualBox NIC trace, 60 s).
This script computes their 145 network columns from the first 20 s of that traffic with the release's switch model
and summary (verified first: it reproduces a dataset row from its own capture), puts them in place of the five
rows' network columns, and re-scores the paper's two evaluations with the paper's detectors (common.py):
  Table IV  held-out split, forest seed 42 and the mean of seeds 42, 0-9 (training rows unchanged, so only the five
            test rows' scores move);
  Table V   combined pool, 10 fold assignments.
Two variants of the five rows:
  b_all   all traffic as recorded: DNS and port 8080 to the Sink (answered) and port 8080 to public addresses, which
          nothing answers in the sealed lab (the lab cue of cue/unanswered_cue.py);
  b_sink  only the traffic with the Sink (all answered): what is left without the cue.
Host columns stay as collected (the bots quitting): B has no system-call data, so the hybrid estimate mixes a running
bot's traffic with a quitting bot's host behaviour. Post hoc, on already-examined data; an estimate, not a result.

    nice -n 19 /usr/bin/python3 visibility/counterfactual.py
"""
import csv
import importlib.util
import ipaddress
import json
import struct
import sys
import tempfile
from multiprocessing import Pool
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
EVAL = HERE.parent
sys.path.insert(0, str(EVAL))
import common as C  # noqa: E402

VIS = EVAL.parent / "sensor-visibility/runs/20261115T194338586321Z"
OUT = EVAL / "results" / "visibility_counterfactual.json"
RF_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
LAB = ipaddress.ip_network("10.0.0.0/8")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


sm = _load("switch_model", C.RELEASE / "features" / "switch_model.py")


def net_row(pcap, start_us, net_cols):
    """The 145 network columns of a capture: 40 windows of 0.5 s from start_us, five summaries per signal."""
    windows = sm.window_features(str(pcap), start_us, window_seconds=0.5, windows=40)
    sigs = C.signals(net_cols)
    W = np.asarray([[w[s] for s in sigs] for w in windows], dtype=float)[None, :, :]   # n, windows, signals
    return C.summarize(W)[0]


def sink_only(src, dst):
    """Copy of a classic pcap keeping only frames whose IPv4 source and destination are both in the lab (the Sink)."""
    with open(src, "rb") as f:
        header = f.read(24)
        order = "<" if header[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        out = [header]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            n = struct.unpack(order + "IIII", rec)[2]
            frame = f.read(n)
            if len(frame) >= 34 and frame[12:14] == b"\x08\x00":
                s, d = ipaddress.ip_address(frame[26:30]), ipaddress.ip_address(frame[30:34])
                if s not in LAB or d not in LAB:
                    continue
            out.append(rec + frame)
    Path(dst).write_bytes(b"".join(out))


def first_record_us(pcap):
    for time_us, _ts, _frame in sm.read_pcap(str(pcap)):
        return time_us
    return 0


def _fp(args):
    Xh, Xn, y, g, tr, te, s = args
    return s, C.fit_predict(Xh, Xn, y, g, tr, te, rf_seed=s)


def table_iv(rows, Xh, Xn, y, g):
    cats = np.asarray([r["category"] for r in rows])
    split = np.asarray([r["split"] for r in rows])
    gen = np.isin(cats, ("malware", "benign"))
    tr, te = np.flatnonzero(gen & (split == "train")), np.flatnonzero(gen & (split == "test"))
    with Pool(11) as pool:
        res = dict(pool.map(_fp, [(Xh, Xn, y, g, tr, te, s) for s in RF_SEEDS], chunksize=1))
    out = {}
    for d in C.DETECTORS:
        m42 = C.metrics(y[te], res[42][d])
        out[d] = {"rf42": {k: m42[k] for k in ("balanced_accuracy", "auc", "tn", "fp", "fn", "tp")},
                  "ba_mean_11_seeds": float(np.mean([C.metrics(y[te], res[s][d])["balanced_accuracy"] for s in RF_SEEDS])),
                  "ba_sd_11_seeds": float(np.std([C.metrics(y[te], res[s][d])["balanced_accuracy"] for s in RF_SEEDS], ddof=1))}
    return out, te, res


def table_v(Xh, Xn, y, g):
    P, _ = C.cv_all(Xh, Xn, y, g)
    per = {d: [C.metrics(y, P[d][s])["balanced_accuracy"] for s in range(10)] for d in C.DETECTORS}
    return {d: {"ba_mean": float(np.mean(v)), "ba_sd": float(np.std(v, ddof=1)), "per_assignment": v}
            for d, v in per.items()}, P


def main():
    rows, host_cols, net_cols = C.load()
    Xh, Xn0, y, g = C.matrix(rows, host_cols), C.matrix(rows, net_cols), C.labels(rows), C.groups_published(rows)
    idx = {r["sha256"]: i for i, r in enumerate(rows) if r["category"] == "malware"}

    # 1. the feature code reproduces a dataset row from its own capture (a malware row with traffic)
    dirs = C.run_dirs(rows)
    check = None
    for i, r in enumerate(rows):
        if r["category"] == "malware" and float(r["net_pkts_total_delta__sum"]) > 50:
            out_dir = C.output_dir(dirs[i])
            meta = json.load(open(out_dir / "run.json"))
            got = net_row(out_dir / "packet_capture.pcap", int(meta["sample_started_wall_us"]), net_cols)
            rel = float(np.max(np.abs(got - Xn0[i]) / np.maximum(np.abs(Xn0[i]), 1e-12)))
            check = {"sample": r["sha256"][:16], "max_rel_diff": rel}
            break
    assert check and check["max_rel_diff"] < 1e-9, check
    print("feature code reproduces the dataset row:", check, flush=True)

    # 2. the five Tsunami rows from the B recordings
    variants, details = {"b_all": Xn0.copy(), "b_sink": Xn0.copy()}, {}
    case_dirs = sorted(p for p in (VIS / "phases/collect-b").iterdir() if p.is_dir())
    tsunami = [p for p in case_dirs if json.load(open(p / "run.json")).get("family") == "Tsunami"]
    assert len(tsunami) == 5, len(tsunami)
    with tempfile.TemporaryDirectory(prefix="hz-cf-") as tmp:
        for p in tsunami:
            rec = json.load(open(p / "run.json"))
            sha = rec["sample"][:-4]
            i = idx[sha]
            assert rows[i]["split"] == "test" and float(rows[i]["net_pkts_total_delta__sum"]) == 0
            start_us = first_record_us(p / "nic.pcap") + int((rec["launched_ns"] - rec["power_requested_ns"]) / 1000) - 300_000
            variants["b_all"][i] = net_row(p / "nic.pcap", start_us, net_cols)
            sink_only(p / "nic.pcap", Path(tmp) / "sink.pcap")
            variants["b_sink"][i] = net_row(Path(tmp) / "sink.pcap", start_us, net_cols)
            col = {c: j for j, c in enumerate(net_cols)}
            details[sha[:16]] = {v: {"packets": variants[v][i][col["net_pkts_total_delta__sum"]],
                                     "flows_max": variants[v][i][col["net_flow_count_seen__max"]],
                                     "reverse_packets": variants[v][i][col["net_pkts_ba_delta__sum"]]}
                                 for v in variants}
    print("five rows:", json.dumps(details), flush=True)

    # 3. re-score
    result = {"check": check, "five_rows": details, "table_iv": {}, "table_v": {}, "five_rows_scores": {}}
    for name, Xn in (("as_collected", Xn0), ("b_all", variants["b_all"]), ("b_sink", variants["b_sink"])):
        t4, te, res = table_iv(rows, Xh, Xn, y, g)
        result["table_iv"][name] = t4
        five = [list(te).index(idx[s]) for s in [p.name for p in tsunami]]
        result["five_rows_scores"][name] = {d: [float(res[42][d][j]) for j in five] for d in C.DETECTORS}
        t5, _ = table_v(Xh, Xn, y, g)
        result["table_v"][name] = t5
        print(name, "Table IV BA (seed 42):", {d: round(t4[d]["rf42"]["balanced_accuracy"], 3) for d in C.DETECTORS},
              "| Table V BA:", {d: round(t5[d]["ba_mean"], 3) for d in C.DETECTORS}, flush=True)
    assert abs(result["table_iv"]["as_collected"]["network"]["rf42"]["balanced_accuracy"] - 0.75) < 1e-9
    assert abs(result["table_v"]["as_collected"]["stacked"]["ba_mean"] - 0.823) < 6e-4
    C.write_json(OUT, result)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
