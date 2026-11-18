"""How much of the network view rests on connections nobody answered? Offline (committee item 2; REPORT 2.7).

In the sealed lab only the Sink (10.0.0.1) answers; a packet to any other address is dropped. The benign programs
talk to the Sink, so only malware (and some attack runs) leave TCP/UDP flows unanswered, and the network detector can
learn "nobody answered" as a malware cue that a real network would not give. Protocol, definitions and decision rules
were written before this script ran: results/unanswered_cue_protocol.json.

  A. per run, from the original capture: TCP/UDP flows in the 40 feature windows and how many got no packet back
  B. Table V (cached out-of-fold predictions): recall and false alarms by run class; the cue and traffic rules
  C. Table IV (cached held-out predictions): the same on the 54 test rows
  D. cue-free retraining with the Table V protocol (rules R1, R2)
  E. Table IV with the cue runs removed from training
  F. the 28 C2/backdoor malware of the sinkhole run (every connection answered) against their own 20-s runs of
     2026-10-25 (no connection answered), and the sinkhole run's 28 benign clients

    nice -n 19 /usr/bin/python3 cue/unanswered_cue.py
"""
import csv
import glob
import importlib.util
import ipaddress
import json
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
EVAL = HERE.parent
sys.path.insert(0, str(EVAL))
import common as C  # noqa: E402

STUDY = EVAL.parent
SINK_RUN = STUDY / "sinkhole-c2-5min" / "20261113T084625506148Z"
PAST = [STUDY / "c2-viability" / "20261025T142642347649Z", STUDY / "evasive-viability" / "20261025T151638248361Z"]
EXT_AUDIT = STUDY / "extension-audit-20261112" / "extension_audit-20261112T184152Z.json"
PROTOCOL = EVAL / "results" / "unanswered_cue_protocol.json"
OUT = EVAL / "results" / "unanswered_cue.json"
FLOWS_CSV = HERE / "run_flows.csv"
SINK = "10.0.0.1"
CLASSES = ("silent", "all_answered", "some_unanswered", "none_answered")
CUE = ("some_unanswered", "none_answered")
RF_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


sm = _load("switch_model", C.RELEASE / "features" / "switch_model.py")


# ------------------------------------------------------------------------------------------------ A. flows
def dest_kind(addr):
    if addr == SINK:
        return "sink"
    ip = ipaddress.ip_address(addr)
    if ip.is_multicast or addr == "255.255.255.255" or addr.endswith(".255"):
        return "broadcast_multicast"
    if ip in ipaddress.ip_network("10.0.0.0/24"):
        return "guest_subnet"
    if ip.is_private:
        return "other_private"
    return "public"


def run_flows(pcap, start_us, windows=40, window_us=500_000):
    """Packets and bidirectional flows (IPv4 TCP/UDP) in the feature windows; flow = [first src, first dst, fwd, rev]."""
    flows, n = {}, 0
    for time_us, _ts, frame in sm.read_pcap(str(pcap)):
        off = time_us - start_us
        if off < 0 or off // window_us >= windows:
            continue
        p = sm.parse_flow_packet(frame)
        if p is None:
            continue
        n += 1
        src, dst, proto, ports, _flags = p
        a, b = (src, ports[0]), (dst, ports[1])
        key = (proto,) + ((a, b) if a <= b else (b, a))
        f = flows.get(key)
        if f is None:
            flows[key] = f = [a, b, 0, 0]
        if (a, b) == (f[0], f[1]):
            f[2] += 1
        else:
            f[3] += 1
    return n, flows


def describe(n, flows):
    unanswered = [f for f in flows.values() if f[3] == 0]
    if not flows:
        cls = "silent"
    elif not unanswered:
        cls = "all_answered"
    elif len(unanswered) == len(flows):
        cls = "none_answered"
    else:
        cls = "some_unanswered"
    kinds = {}
    for f in unanswered:
        k = dest_kind(f[1][0])
        kinds[k] = kinds.get(k, 0) + 1
    return {"packets": n, "flows": len(flows), "unanswered_flows": len(unanswered), "class": cls,
            "unanswered_by_destination": kinds}


def _flow_job(args):
    out_dir = Path(args)
    meta = json.load(open(out_dir / "run.json"))
    n, flows = run_flows(out_dir / "packet_capture.pcap", int(meta["sample_started_wall_us"]))
    return describe(n, flows)


def output_dir(run_dir):
    hits = sorted(glob.glob(str(Path(run_dir) / "output" / "run_*")))
    assert len(hits) == 1, run_dir
    return Path(hits[0])


# ---------------------------------------------------------------------------------------------- helpers
def flag_rate(P, idx):
    """Mean over assignments of the share of rows idx flagged at 0.5 (P: assignments x rows)."""
    return float((P[:, idx] >= 0.5).mean()) if len(idx) else None


def ba_rows(y, flag):
    return float(C.ba(y, flag.astype(int)))


def subgroup_table(P, cats, cls, y, idx_rows=None):
    """Flag rate per detector for every (category, run class) present among idx_rows."""
    idx_rows = np.arange(len(y)) if idx_rows is None else idx_rows
    out = {}
    for cat in sorted(set(cats[idx_rows])):
        for c in CLASSES:
            idx = idx_rows[(cats[idx_rows] == cat) & (cls[idx_rows] == c)]
            if len(idx):
                out["%s/%s" % (cat, c)] = {"n": int(len(idx)), **{d: flag_rate(P[d], idx) for d in P}}
    return out


def tel_summary(out_dir, hs, ns, k=40):
    tel = list(csv.DictReader(open(Path(out_dir) / "telemetry.csv", newline="", encoding="utf-8-sig")))
    assert len(tel) >= k, out_dir
    H = np.asarray([[[float(w[s]) for s in hs] for w in tel[:k]]])
    N = np.asarray([[[float(w[s]) for s in ns] for w in tel[:k]]])
    return C.summarize(H)[0], C.summarize(N)[0]


def _fp_job(args):
    Xh, Xn, y, g, tr, te, seed = args
    return seed, C.fit_predict(Xh, Xn, y, g, tr, te, seed)


def confusion(y, p):
    m = C.metrics(y, p)
    return {k: m[k] for k in ("balanced_accuracy", "tn", "fp", "fn", "tp")}


# ------------------------------------------------------------------------------------------------- main
def main():
    proto = json.load(open(PROTOCOL))
    rows, hc, nc = C.load()
    y = C.labels(rows)
    Xh, Xn = C.matrix(rows, hc), C.matrix(rows, nc)
    cats = np.asarray([r["category"] for r in rows])
    groups = C.groups_published(rows)
    result = {"protocol_written_utc": proto["written_utc"]}

    # A. flows of every run
    dirs = [C.output_dir(d) for d in C.run_dirs(rows)]
    with Pool(12) as pool:
        info = pool.map(_flow_job, [str(d) for d in dirs], chunksize=1)
    cls = np.asarray([i["class"] for i in info])
    pk_sum = Xn[:, nc.index("net_pkts_total_delta__sum")]
    ab_sum = Xn[:, nc.index("net_pkts_ab_delta__sum")]
    ba_sum = Xn[:, nc.index("net_pkts_ba_delta__sum")]
    mismatch = [rows[i]["execution_id"] for i in range(len(rows)) if int(round(pk_sum[i])) != info[i]["packets"]]
    assert not mismatch, mismatch
    rowlevel_none = (ab_sum > 0) & (ba_sum == 0)
    flowlevel_none = cls == "none_answered"
    with open(FLOWS_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["execution_id", "category", "family", "project", "split", "packets", "flows",
                    "unanswered_flows", "class", "unanswered_by_destination"])
        for r, i in zip(rows, info):
            w.writerow([r["execution_id"], r["category"], r["family"], r["project"], r["split"], i["packets"],
                        i["flows"], i["unanswered_flows"], i["class"], json.dumps(i["unanswered_by_destination"])])
    counts = {}
    for cat in sorted(set(cats)):
        counts[cat] = {c: int(((cats == cat) & (cls == c)).sum()) for c in CLASSES}
    dest = {}
    for cat in sorted(set(cats)):
        agg = {}
        for i in np.flatnonzero(cats == cat):
            for k, v in info[i]["unanswered_by_destination"].items():
                agg[k] = agg.get(k, 0) + v
        dest[cat] = agg
    cue = np.isin(cls, CUE)
    traffic = cls != "silent"
    result["A_flows"] = {
        "packets_equal_feature_sum_all_240": True,
        "row_level_no_reverse_packet_vs_flow_level_none_answered_agree": int((rowlevel_none == flowlevel_none).sum()),
        "runs_by_class": counts, "unanswered_flows_by_destination": dest,
        "families_with_cue_runs": sorted({rows[i]["family"] for i in np.flatnonzero(cue & (cats == "malware"))}),
        "cue_runs_by_family": {f: int(((cue) & (cats == "malware") & (np.asarray([r["family"] for r in rows]) == f)).sum())
                               for f in sorted({r["family"] for r in rows if r["category"] == "malware"})},
        "attack_cue_runs": sorted(rows[i]["execution_id"] for i in np.flatnonzero(cue & (cats == "network_attack")))}
    print("A", json.dumps(counts), flush=True)

    # B. Table V, cached out-of-fold predictions
    z = np.load(C.CACHE / "cv_published_k40.npz", allow_pickle=False)
    assert list(z["seeds"]) == C.FOLD_SEEDS
    P = {d: z[d] for d in C.DETECTORS}
    pub = {d: float(np.mean([C.metrics(y, P[d][s])["balanced_accuracy"] for s in range(10)])) for d in C.DETECTORS}
    for d, v in {"host": 0.784, "network": 0.756, "concat": 0.812, "stacked": 0.823}.items():
        assert abs(pub[d] - v) < 6e-4, (d, pub[d])
    tp_cue = []
    for s in range(10):
        tp = (P["network"][s] >= 0.5) & (y == 1)
        tp_cue.append(float(cue[tp].mean()) if tp.any() else None)
    result["B_table_v"] = {
        "published_ba": pub,
        "flag_rate_by_category_and_class": subgroup_table(P, cats, cls, y),
        "cue_rule_ba": ba_rows(y, cue), "traffic_rule_ba": ba_rows(y, traffic),
        "cue_rule_recall_malicious": float(cue[y == 1].mean()), "cue_rule_false_alarms_benign": float(cue[y == 0].mean()),
        "share_of_network_true_positives_with_cue_mean": float(np.mean(tp_cue))}
    print("B published", {d: round(v, 3) for d, v in pub.items()}, "cue rule BA", round(ba_rows(y, cue), 3), flush=True)

    # C. Table IV, cached held-out predictions
    gen = np.isin(cats, ("malware", "benign"))
    split = np.asarray([r["split"] for r in rows])
    tr, te = np.flatnonzero(gen & (split == "train")), np.flatnonzero(gen & (split == "test"))
    h = np.load(C.CACHE / "heldout_k40.npz", allow_pickle=False)
    assert np.array_equal(h["te"], te)
    want = {"network": (28, 0, 13, 13), "host": (24, 4, 0, 26), "concat": (26, 2, 2, 24), "stacked": (27, 1, 1, 25)}
    for d, cm in want.items():
        m = C.metrics(y[te], h["%s__rf42" % d])
        assert (m["tn"], m["fp"], m["fn"], m["tp"]) == cm, (d, m)
    PH = {d: np.stack([h["%s__rf%d" % (d, s)] for s in RF_SEEDS]) for d in C.DETECTORS}
    PH42 = {d: h["%s__rf42" % d][None, :] for d in C.DETECTORS}
    te_local = np.arange(len(te))
    result["C_table_iv"] = {
        "rf42_by_category_and_class": subgroup_table(PH42, cats[te], cls[te], y[te], te_local),
        "rf_seeds_mean_by_category_and_class": subgroup_table(PH, cats[te], cls[te], y[te], te_local),
        "cue_rule": confusion(y[te], cue[te].astype(float)), "traffic_rule": confusion(y[te], traffic[te].astype(float)),
        "network_rf42_true_positives_with_cue": int(((h["network__rf42"] >= 0.5) & (y[te] == 1) & cue[te]).sum()),
        "network_rf42_true_positives": int(((h["network__rf42"] >= 0.5) & (y[te] == 1)).sum())}
    print("C", result["C_table_iv"]["cue_rule"], flush=True)

    # D. cue-free retraining, Table V protocol
    keep = np.flatnonzero(~cue)
    Pk, _ = C.cv_all(Xh[keep], Xn[keep], y[keep], groups[keep])
    yk, ck, clk = y[keep], cats[keep], cls[keep]
    gen_k = np.isin(ck, ("malware", "benign", "network_benign", "null"))
    tba = ba_rows(yk, traffic[keep])
    per = {d: [C.metrics(yk, Pk[d][s])["balanced_accuracy"] for s in range(10)] for d in C.DETECTORS}
    per_pub = {d: [C.metrics(yk, P[d][s][keep])["balanced_accuracy"] for s in range(10)] for d in C.DETECTORS}
    per_gen = {d: [C.metrics(yk[gen_k], Pk[d][s][gen_k])["balanced_accuracy"] for s in range(10)] for d in C.DETECTORS}
    r1 = sum(per["network"][s] - max(0.5, tba) >= 0.05 for s in range(10))
    r2 = {d: sum(per[d][s] - per["host"][s] >= 0.02 for s in range(10)) for d in ("stacked", "concat")}
    result["D_cue_free_table_v"] = {
        "rows": int(len(keep)), "malicious": int((yk == 1).sum()), "benign": int((yk == 0).sum()),
        "ba_mean": {d: float(np.mean(v)) for d, v in per.items()},
        "ba_sd": {d: float(np.std(v, ddof=1)) for d, v in per.items()},
        "ba_per_assignment": per,
        "published_models_on_same_rows_ba_mean": {d: float(np.mean(v)) for d, v in per_pub.items()},
        "ba_mean_without_attack_runs_in_scoring": {d: float(np.mean(v)) for d, v in per_gen.items()},
        "traffic_rule_ba": tba,
        "flag_rate_by_category_and_class": subgroup_table(Pk, ck, clk, yk),
        "R1_network_beyond_cue": {"assignments_meeting": int(r1),
                                  "verdict": "signal beyond the cue" if r1 >= 8 else "no clear signal beyond the cue"},
        "R2_hybrid_edge_without_cue": {d: {"assignments_meeting": int(r2[d]),
                                           "gain_mean": float(np.mean(np.subtract(per[d], per["host"]))),
                                           "verdict": "edge holds" if r2[d] >= 8 else "no clear edge"}
                                       for d in r2}}
    print("D", {d: round(float(np.mean(v)), 3) for d, v in per.items()}, "R1", r1, "R2", r2, flush=True)

    # E. Table IV with the cue runs removed from training
    tr_cf = np.asarray([i for i in tr if not cue[i]])
    with Pool(11) as pool:
        res = dict(pool.map(_fp_job, [(Xh, Xn, y, groups, tr_cf, te, s) for s in RF_SEEDS], chunksize=1))
    PE = {d: np.stack([res[s][d] for s in RF_SEEDS]) for d in C.DETECTORS}
    te_cf = np.flatnonzero(~cue[te])
    result["E_table_iv_cue_free_training"] = {
        "train_rows": int(len(tr_cf)), "train_malware": int((y[tr_cf] == 1).sum()), "test_rows": int(len(te)),
        "cue_free_test_rows": int(len(te_cf)),
        "rf42_all_test": {d: confusion(y[te], res[42][d]) for d in C.DETECTORS},
        "rf42_cue_free_test": {d: confusion(y[te][te_cf], res[42][d][te_cf]) for d in C.DETECTORS},
        "published_rf42_cue_free_test": {d: confusion(y[te][te_cf], h["%s__rf42" % d][te_cf]) for d in C.DETECTORS},
        "ba_mean_all_test": {d: float(np.mean([C.metrics(y[te], PE[d][k])["balanced_accuracy"] for k in range(11)]))
                             for d in C.DETECTORS},
        "ba_mean_cue_free_test": {d: float(np.mean([C.metrics(y[te][te_cf], PE[d][k][te_cf])["balanced_accuracy"]
                                                    for k in range(11)])) for d in C.DETECTORS},
        "rf_seeds_by_category_and_class": subgroup_table(PE, cats[te], cls[te], y[te], te_local)}
    print("E", result["E_table_iv_cue_free_training"]["rf42_all_test"], flush=True)

    # F. sinkhole run (answered) vs the same samples' 20-s runs of 2026-10-25 (unanswered)
    hs, ns = C.signals(hc), C.signals(nc)
    sink_cases = json.load(open(SINK_RUN / "protocol.json"))["cases"]
    sink_val = json.load(open(sorted(SINK_RUN.glob("validation-*.json"))[-1]))
    ok_now = {c["sample"] for c in sink_val["results"] if c["status"] == "accepted"}
    ext = json.load(open(EXT_AUDIT))
    ok_past = {c["sample"] for c in ext["results"]
               if c["status"] == "accepted" and c["batch"] in ("C2 probe", "backdoor probe") and c["label"] == "malware"}
    mal = [c for c in sink_cases if c["label"] == "malware"]
    ben = [c for c in sink_cases if c["label"] == "benign"]
    assert len(mal) == 28 and len(ben) == 28
    new_h, new_n, meta = [], [], []
    for c in mal:
        s = c["sample"]
        past_dir = [p / "runs" / s for p in PAST if (p / "runs" / s).is_dir()]
        assert len(past_dir) == 1 and s in ok_now and s in ok_past, s
        for when, d in (("past", output_dir(past_dir[0])), ("now", output_dir(SINK_RUN / "runs" / s))):
            hh, nn = tel_summary(d, hs, ns)
            new_h.append(hh), new_n.append(nn)
            meta.append({"sample": s, "family": c.get("family"), "when": when, **_flow_job(str(d))})
    for c in ben:
        s = c["sample"]
        assert s in ok_now, s
        d = output_dir(SINK_RUN / "runs" / s)
        hh, nn = tel_summary(d, hs, ns)
        new_h.append(hh), new_n.append(nn)
        meta.append({"sample": s, "family": None, "when": "benign_now", **_flow_job(str(d))})
    XH, XN = np.vstack([Xh, np.asarray(new_h)]), np.vstack([Xn, np.asarray(new_n)])
    YY = np.concatenate([y, np.zeros(len(new_h), dtype=int)])
    GG = np.concatenate([groups, np.asarray(["new"] * len(new_h), dtype=object)])
    te_new = np.arange(len(y), len(YY))
    with Pool(2) as pool:
        fp = pool.map(_fp_job, [(XH, XN, YY, GG, tr, te_new, 42), (XH, XN, YY, GG, np.arange(len(y)), te_new, 42)])
    models = {"table_iv_detectors": fp[0][1], "all_240_detectors": fp[1][1]}
    when = np.asarray([m["when"] for m in meta])
    summary = {}
    for mname, probs in models.items():
        summary[mname] = {w: {d: int((probs[d][when == w] >= 0.5).sum()) for d in C.DETECTORS}
                          for w in ("past", "now", "benign_now")}
        for i, m in enumerate(meta):
            m.setdefault("prob", {})[mname] = {d: float(probs[d][i]) for d in C.DETECTORS}
    paired = [(meta[2 * k], meta[2 * k + 1]) for k in range(28)]
    assert all(a["sample"] == b["sample"] and a["when"] == "past" and b["when"] == "now" for a, b in paired)
    result["F_sinkhole_vs_past"] = {
        "flags_of_28": summary,
        "past_runs_by_class": {c: sum(a["class"] == c for a, _ in paired) for c in CLASSES},
        "now_runs_by_class": {c: sum(b["class"] == c for _, b in paired) for c in CLASSES},
        "benign_now_by_class": {c: sum(m["class"] == c for m in meta if m["when"] == "benign_now") for c in CLASSES},
        "per_sample": meta}
    print("F", json.dumps(summary), flush=True)
    C.write_json(OUT, result)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
