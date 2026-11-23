#!/usr/bin/env python3
"""The lab workstation's check of PC1.md parts 13C and 13K (2026-11-20), standard library only.

    check_13ck.py P4_EBPF_DIR PART13_DIR PART13C_DIR PART13K_DIR OUT_JSON

P4_EBPF_DIR: the repository (live_test/streaming/dataset_windows.csv.gz, dataset_windows_0.25s.csv.gz,
dataset_windows_0.25s.json, net_windows_0.25s.csv.gz). PART13*_DIR: part13_20261120 of the archives
pc1_20261120_part13.tar.xz, pc1_20261120_part13c.tar.xz and pc1_20261120_part13k.tar.xz.

13H: the 0.25 s table against the 0.5 s one (calls, transitions, the bounds of each maximum, empty windows), the
report's counts, and the network half against PC1's net_windows_0.25s.csv.gz. 13J/13L: from the raw timing.jsonl and
block.jsonl of each run, the markers' lateness (each marker's send time after its boundary; the run's first marker,
which starts window 0, left out), the switch's window lengths (the markers' send times on the switch), each score's
time after its window's end, and the alarms; the tables' "median" is the median of the per-run medians. Also the
fetch of each window: when it was asked after the window's end, how long the reader held it, and its register read.
"""
import csv
import glob
import gzip
import json
import os
import statistics as st
import sys

HOST_MAX_BOUNDS = {          # 13H's bounds: the 0.5 s value against its two 0.25 s halves A and B
    "host_unique_syscalls_max": "max(A,B)..A+B", "host_max_run_length_max": "max(A,B)..A+B",
    "host_first50_unique_max": "A..A+B", "host_first100_unique_max": "A..A+B",
    "host_top_syscall_freq_max": "<=max(A,B)", "host_rare_syscall_ratio_max": "<=max(A,B)",
    "host_avg_run_length_max": "<=A+B", "host_entropy_max": "<=max(A,B)+1",
}


def table(path):
    with gzip.open(path, "rt", newline="") as f:
        r = csv.reader(f)
        h = next(r)
        ix = {c: i for i, c in enumerate(h)}
        return h, {(row[0], int(row[ix["window"]])): row for row in r}, ix


def check_13h(repo):
    s = os.path.join(repo, "live_test/streaming")
    h, T5, ix = table(os.path.join(s, "dataset_windows.csv.gz"))
    h25, T25, ix25 = table(os.path.join(s, "dataset_windows_0.25s.csv.gz"))
    assert h == h25
    f = lambda row, c: float(row[ix[c]])
    ids = sorted({k[0] for k in T5})
    out = dict(runs=len(ids), windows_05=len(T5), windows_025=len(T25))
    out["calls"] = [sum(f(T5[k], "host_total_syscalls_total") for k in T5),
                    sum(f(T25[k], "host_total_syscalls_total") for k in T25)]
    tr5 = sum(f(T5[k], "host_transition_count_total") for k in T5)
    tr25 = sum(f(T25[k], "host_transition_count_total") for k in T25)
    viol = {c: 0 for c in HOST_MAX_BOUNDS}
    viol.update(calls=0, transitions=0, empty=0, metadata=0)
    lost_windows = 0
    for e in ids:
        for w in range(40):
            W, A, B = T5[(e, w)], T25[(e, 2 * w)], T25[(e, 2 * w + 1)]
            if [A[ix[m]] for m in ("label", "category", "cv_group", "split")] != \
                    [W[ix[m]] for m in ("label", "category", "cv_group", "split")]:
                viol["metadata"] += 1
            ca, cb, cw = (f(x, "host_total_syscalls_total") for x in (A, B, W))
            viol["calls"] += abs(cw - ca - cb) > 1e-9
            lost = f(W, "host_transition_count_total") - f(A, "host_transition_count_total") \
                - f(B, "host_transition_count_total")
            lost_windows += lost > 0
            viol["transitions"] += not (-1e-9 <= lost <= min(ca, cb) + 1e-9)
            for c, rule in HOST_MAX_BOUNDS.items():
                a, b, v = f(A, c), f(B, c), f(W, c)
                ok = {"max(A,B)..A+B": max(a, b) - 1e-9 <= v <= a + b + 1e-9, "A..A+B": a - 1e-9 <= v <= a + b + 1e-9,
                      "<=max(A,B)": v <= max(a, b) + 1e-9, "<=A+B": v <= a + b + 1e-9,
                      "<=max(A,B)+1": v <= max(a, b) + 1 + 1e-9}[rule]
                viol[c] += not ok
            empty_w, empty_ab = cw == 0, ca == 0 and cb == 0
            zero_w = all(float(W[ix[c]]) == 0 for c in h if c.startswith("host_"))
            viol["empty"] += (empty_w != empty_ab) or (empty_w and not zero_w)
    out.update(transitions_05=tr5, transitions_lost=tr5 - tr25, windows_with_lost_transitions=lost_windows,
               violations=viol)
    rep = json.load(open(os.path.join(s, "dataset_windows_0.25s.json")))
    runs = rep["runs"].values()
    iv = [v["start_interval_us"] for v in runs]
    out["report"] = dict(matched_by={k: sum(1 for v in runs if v["matched_by"] == k) for k in ("run_id", "name")},
                         start_interval_under_10us=sum(x < 10 for x in iv), under_1ms=sum(x < 1000 for x in iv),
                         over_100ms=sum(x > 100000 for x in iv), calls=rep["calls"], uncertain=rep["uncertain_calls"])
    hn, Tn, ixn = table(os.path.join(s, "net_windows_0.25s.csv.gz"))
    net = [c for c in hn if c.startswith("net_")]
    out["network_half"] = dict(cells=len(Tn) * len(net),
                               differing=sum(1 for k, r in Tn.items() for c in net if r[ixn[c]] != T25[k][ix25[c]]))
    return out


def jl(p):
    with open(p) as fh:
        return [json.loads(x) for x in fh if x.strip()]


def run_timing(timing):
    T = sorted(jl(timing), key=lambda r: r["window"])
    late = [1000 * (r["marked"]["collector_t_sent"] - r["t_window_end"]) for r in T if r.get("marked")]
    sent = [r["marked"]["t_sent"] for r in T if r.get("marked")]
    wlen = [1000 * (b - a) for a, b in zip(sent, sent[1:])]
    end = {r["window"]: r["t_window_end"] for r in T}
    blk = timing.replace(".timing.jsonl", ".block.jsonl")
    B = jl(blk) if os.path.exists(blk) else []
    score = [1000 * (e["time"] - end[e["window"]]) for e in B if e.get("event") == "score" and e["window"] in end]
    score_ms = [e["score_ms"] for e in B if e.get("event") == "score"]
    alarm = [e for e in B if e.get("event") == "alarm"]
    late_windows = [(r["window"], round(1000 * (r["marked"]["collector_t_sent"] - r["t_window_end"]), 1))
                    for r in T if r.get("marked") and r["marked"]["collector_t_sent"] - r["t_window_end"] > 0.005]
    return dict(windows=len(T), lost=sum(1 for r in T if r.get("lost")),
                marker_late_ms=dict(median=round(st.median(late), 2), max=round(max(late), 1)),
                markers_over_5ms_late=late_windows,
                switch_window_ms=dict(median=round(st.median(wlen), 1), max=round(max(wlen), 1)),
                score_after_window_end_ms=(dict(median=round(st.median(score), 1), max=round(max(score), 1))
                                           if score else None),
                score_ms_median=round(st.median(score_ms), 1) if score_ms else None,
                alarm=(dict(window=alarm[0]["window"], p=alarm[0]["probability"],
                            after_window_end_ms=round(1000 * (alarm[0]["time"] - end[alarm[0]["window"]]), 1))
                       if alarm else None),
                fetch=dict(asked_after_window_end_ms=round(st.median(
                               [1000 * (r["collector_t_sent"] - r["t_window_end"]) for r in T]), 1),
                           reader_held_ms=round(st.median([1000 * (r["reader_t_send"] - r["reader_t_recv"]) for r in T]), 1),
                           reply_after_window_end_ms=round(st.median(
                               [1000 * (r["collector_t_reply"] - r["t_window_end"]) for r in T]), 1),
                           register_read_ms=round(st.median([r["read_ms"] for r in T]), 1)))


def config(d):
    runs = {os.path.basename(t)[:-len(".timing.jsonl")]: run_timing(t)
            for t in sorted(glob.glob(os.path.join(d, "*.timing.jsonl")))}
    summ = json.load(open(os.path.join(d, "summary.json"))) if os.path.exists(os.path.join(d, "summary.json")) else {}
    med = lambda key, sub: round(st.median(r[key][sub] for r in runs.values() if r[key]), 2)
    mx = lambda key, sub: max(r[key][sub] for r in runs.values() if r[key])
    table = dict(marker_late_ms=[med("marker_late_ms", "median"), mx("marker_late_ms", "max")],
                 switch_window_ms=[med("switch_window_ms", "median"), mx("switch_window_ms", "max")],
                 score_after_window_end_ms=[med("score_after_window_end_ms", "median"),
                                            mx("score_after_window_end_ms", "max")])
    floods = {c: dict(alarm=r["alarm"], dropped=summ.get(c, {}).get("dropped"), sent=summ.get(c, {}).get("sent"),
                      pc2_rx=summ.get(c, {}).get("pc2_rx_run"))
              for c, r in runs.items() if r["alarm"]}
    benign_max_p = {c: v.get("max_p") for c, v in summ.items() if v.get("alarm_window") is None}
    return dict(table=table, floods=floods, benign_max_p=benign_max_p, runs=runs)


def main():
    repo, p13, p13c, p13k, out = sys.argv[1:6]
    res = dict(check_13h=check_13h(repo), timing={
        "stacked serial (13J)": config(os.path.join(p13c, "live_stacked/st_0.25s")),
        "stacked serial 0.5 s (13J)": config(os.path.join(p13c, "live_stacked/st_0.5s")),
        "stacked overlapped (13K)": config(os.path.join(p13k, "live_overlap/st_0.25s")),
        "network serial (13G)": config(os.path.join(p13, "live_attack/net_0.25s")),
        "network overlapped (13K)": config(os.path.join(p13k, "live_overlap/net_0.25s"))})
    with open(out, "w") as fh:
        json.dump(res, fh, indent=1)
        fh.write("\n")
    h = res["check_13h"]
    print("13H: %d runs; calls %d / %d; transitions %d, lost %d in %d windows; violations %s; report %s; network half "
          "%d cells, %d differing" % (h["runs"], h["calls"][0], h["calls"][1], h["transitions_05"], h["transitions_lost"],
                                      h["windows_with_lost_transitions"], h["violations"], h["report"],
                                      h["network_half"]["cells"], h["network_half"]["differing"]))
    for name, c in res["timing"].items():
        print("%-28s markers late %s ms, switch windows %s ms, score after window end %s ms" % (
            name, c["table"]["marker_late_ms"], c["table"]["switch_window_ms"], c["table"]["score_after_window_end_ms"]))
        for run, f in c["floods"].items():
            print("    %-14s alarm %s; dropped %s of %s" % (run, f["alarm"], f["dropped"], f["sent"]))
        for run, r in c["runs"].items():
            if r["markers_over_5ms_late"]:
                print("    %-14s markers over 5 ms late (window, ms): %s" % (run, r["markers_over_5ms_late"][:12]))
        print("    fetch (per-run medians): asked %s ms after the window's end, held %s ms by the reader, register read "
              "%s ms" % (sorted({r["fetch"]["asked_after_window_end_ms"] for r in c["runs"].values()})[::max(1, len(c["runs"]) - 1)],
                         sorted({r["fetch"]["reader_held_ms"] for r in c["runs"].values()})[::max(1, len(c["runs"]) - 1)],
                         sorted({r["fetch"]["register_read_ms"] for r in c["runs"].values()})[::max(1, len(c["runs"]) - 1)]))


if __name__ == "__main__":
    main()
