#!/usr/bin/env python3
"""The session dataset (session-lab base/20261117c, primary view: 435 rows) with 0.25-s and 0.1-s network windows.
Offline; the session lab's own code is imported unchanged.

    /usr/bin/python3 build_session_short.py OUTDIR [--jobs 12]

What can and cannot be recomputed:
  network  yes. Each session's Sink capture has every packet's time. analyze_session_lab.py cuts a session into
           0.5-s windows of 500,000 x (1 + slope) capture microseconds from the session start t0 (the guest's clock
           mapped onto the Sink's capture clock). Here each of those windows is split into 0.5/W equal parts: a
           packet's W window is its 0.5-s window times 0.5/W plus its part, so the W windows nest exactly in the
           published 0.5-s windows. The injected program's flows (socket tracer, relayed DNS) come from
           analyze_session_lab.session_report; the counters from the release switch_model.FlowTable (TTL 3
           windows, rates over the nominal W), as in analyze_session_lab.network_windows.
  host     no. The in-kernel monitor kept one row of statistics per process and 0.5-s window, not the calls. The
           host columns stay the published 0.5-s ones over the same span.
Rows: the base's primary view (relaxed rule, sessions view) in the base's order, from build_base.py itself (with
with_runs.py's two benign batches, as final_netbenign.sh built it). A row spans 20 s or 80 s from the 0.5-s window
of the injection, so its network and host columns cover the same span at every W.
Gate (W = 0.5): the rebuilt per-window network features equal the session's windows.json in all its windows, and
the row summaries equal build_base.matrices (the unrounded values behind base/20261117c's CSVs), which also match
the base's CSVs to their 10 significant digits.
Nesting (W < 0.5): the additive network features of every 0.5-s window are the sums of its W windows.

Outputs (OUTDIR):
  session_<ms>ms_<span>.csv     build_base.py's CSV layout (host = the 0.5-s columns); ms 500, 250, 100; span 20s, 80s
  session_windows_<ms>ms.npz    N (435, 160 x 0.5/W, 29): the network windows of each row's 80-s span; with signal
                                names, execution ids, labels and groups
  session_build.json            gates, checks, hashes
"""
import argparse
import csv
import hashlib
import json
import sys
import time
from multiprocessing import Pool
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
SL = HERE.parent / "session-lab"
sys.path.insert(0, str(SL))
import with_runs as WR            # noqa: E402
import build_base as BB           # noqa: E402
import analyze_session_lab as AS  # noqa: E402
import compare_session_lab as CS  # noqa: E402
C, lab, sm = CS.C, CS.lab, AS.sm

EXTRA = {"silentbenign": "20261117T013400746805Z", "netbenign": "20261117T113428913222Z"}
RUNS = ["main", "tpilot", "floods", "triage", "rest", "silentbenign", "netbenign"]
BASE = SL / "base" / "20261117c"
MS = (500, 250, 100)
SPANS = {"20s": 40, "80s": 160}
ADDITIVE_NET = ("net_pkts_total_delta", "net_bytes_total_delta", "net_pkts_ab_delta", "net_bytes_ab_delta",
                "net_pkts_ba_delta", "net_bytes_ba_delta", "net_syn_delta", "net_ack_delta", "net_rst_delta")

for _name, _att in EXTRA.items():
    WR.register(_name, _att)
WR.patch()
_release = list(csv.DictReader(BB.RELEASE.open()))
DS99 = {r["sha256"] for r in _release if r["category"] == "malware"}
REV5 = {c["member_sha256"] for c in lab.load(Path(lab.REV5).parent / "cases.json") if c["label"] == "malware"}
SESSIONS, SKIPPED = BB.load_runs(RUNS)
PS, _UNIQUE, _DROPPED = BB.build_views(SESSIONS, "relaxed", DS99, REV5)
_rows, HOST_COLS, NET_COLS = C.load()
NET_SIGNALS = C.signals(NET_COLS)
PROTOCOLS = {}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def net_windows(pcap, t0_us, n05, win05, keep, ms):
    """analyze_session_lab.network_windows with each 0.5-s window split into 500/ms parts (the same code at 500)."""
    r = 500 // ms
    win = win05 / r
    table = sm.FlowTable(ms / 1000.0, 3)
    result, current = [], 0
    for time_us, timestamp, frame in sm.read_pcap(str(pcap)):
        offset = time_us - t0_us
        if offset < 0 or int(offset // win05) >= n05:
            continue
        k05 = int(offset // win05)
        window = k05 if r == 1 else k05 * r + min(max(int((offset - k05 * win05) // win), 0), r - 1)
        while current < window:
            result.append(table.read_window(current))
            current += 1
        p = sm.parse_flow_packet(frame)
        if p is None:
            continue
        src, dst, proto, ports, flags = p
        if keep is not None and AS.flow_key(proto, src, ports[0], dst, ports[1]) not in keep:
            continue
        table.update(window, timestamp, src, dst, proto, ports, flags, len(frame))
    while current < n05 * r:
        result.append(table.read_window(current))
        current += 1
    return np.asarray([[w[s] for s in NET_SIGNALS] for w in result], dtype=float)


def one(i):
    t0 = time.time()
    s = PS[i]
    att = SL / "runs" / s["attempt"]
    if s["attempt"] not in PROTOCOLS:
        PROTOCOLS[s["attempt"]] = lab.load(att / "protocol.json")
    protocol = PROTOCOLS[s["attempt"]]
    spec = next(x for x in protocol["sessions"] if x["sid"] == s["sid"])
    _report, data = AS.session_report(att, protocol, spec)
    saved = np.asarray([[w[k] for k in NET_SIGNALS] for w in s["W"]["program"]["net"]], dtype=float)
    out = {"i": i, "N": {}}
    for ms in MS:
        out["N"][ms] = net_windows(data["pcap"], data["t0_us"], data["windows"], data["win_us"], data["app_b_keys"], ms)
    N05 = out["N"][500]
    facts = {"sid": s["sid"], "attempt": s["attempt"], "windows": int(data["windows"]),
             "gate_windows_equal": bool(N05.shape == saved.shape and np.array_equal(N05, saved)),
             "gate_windows_max_abs": float(np.max(np.abs(N05 - saved))) if N05.shape == saved.shape else None,
             "program_flows": len(data["app_b_keys"]), "nesting_max_abs": {}}
    ni = [NET_SIGNALS.index(k) for k in ADDITIVE_NET]
    for ms in (250, 100):
        r = 500 // ms
        facts["nesting_max_abs"][str(ms)] = float(np.max(np.abs(
            out["N"][ms][:, ni].reshape(N05.shape[0], r, -1).sum(1) - N05[:, ni])))
    facts["seconds"] = round(time.time() - t0, 2)
    out["facts"] = facts
    return out


def write_csv(path, rows_meta, Xh, Xn):
    """build_base.write_csv's layout and number format."""
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(BB.META + HOST_COLS + NET_COLS)
        for meta, h, n in zip(rows_meta, Xh, Xn):
            w.writerow(meta + ["%.10g" % v for v in h] + ["%.10g" % v for v in n])


def meta_values(s):
    meta = {"execution_id": "%s:%s" % (s["attempt"], s["sid"]), "label": CS.label(s),
            "family": s.get("family", ""), "project": s.get("project", ""), "program": s.get("program", ""),
            "sha256": s.get("sha256", ""), "archive": s.get("archive", ""), "mode": CS.mode_of(s),
            "accepted_relaxed": int(s["accepted_relaxed"]), "accepted_strict": int(s["accepted_strict"])}
    return [meta.get(k, s.get(k, "")) for k in BB.META]


def csv_rel(path, Xh, Xn):
    """Largest relative difference between a base CSV and the given matrices (the CSV holds 10 significant digits)."""
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    A = np.asarray([[float(r[c]) for c in HOST_COLS + NET_COLS] for r in rows])
    B = np.hstack([Xh, Xn])
    return [r["execution_id"] for r in rows], float(np.max(np.abs(A - B) / np.maximum(1.0, np.abs(B))))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("outdir")
    ap.add_argument("--jobs", type=int, default=12)
    args = ap.parse_args()
    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    assert len(PS) == 435, len(PS)
    per = [None] * len(PS)
    with Pool(args.jobs) as pool:
        for res in pool.imap_unordered(one, range(len(PS))):
            per[res["i"]] = res
            f = res["facts"]
            print("[session] %3d %s/%-5s %-9s windows %d flows %5d  gate %s  nest %s  %.1fs" % (
                res["i"], f["attempt"][:15], f["sid"], PS[res["i"]]["kind"], f["windows"], f["program_flows"],
                "ok" if f["gate_windows_equal"] else "DIFF %s" % f["gate_windows_max_abs"],
                f["nesting_max_abs"], f["seconds"]), flush=True)
    facts = [r["facts"] for r in per]
    pi = [int(s["t_inject_s"] // 0.5) for s in PS]
    metas = [meta_values(s) for s in PS]
    report = {"rows": len(PS), "skipped_sessions": SKIPPED,
              "composition": dict(sorted({k: sum(1 for s in PS if s["stratum"] == k)
                                          for k in {s["stratum"] for s in PS}}.items())),
              "gate": {"sessions_windows_equal": sum(f["gate_windows_equal"] for f in facts),
                       "sessions_windows_differ": [f["sid"] + "@" + f["attempt"] for f in facts if not f["gate_windows_equal"]]},
              "nesting_max_abs": {ms: max(f["nesting_max_abs"][ms] for f in facts) for ms in ("250", "100")},
              "per_session": facts, "outputs_sha256": {}}
    for span, n in SPANS.items():
        Xh, Xn05, _pi, hc, nc = BB.matrices(PS, n)
        assert hc == HOST_COLS and nc == NET_COLS and _pi == pi
        for ms in MS:
            r = 500 // ms
            Nw = np.stack([per[i]["N"][ms][pi[i] * r:(pi[i] + n) * r] for i in range(len(PS))])
            Xn = C.summarize(Nw)
            if ms == 500:
                report["gate"]["summary_rel_vs_build_base_%s" % span] = float(
                    np.max(np.abs(Xn - Xn05) / np.maximum(1.0, np.abs(Xn05))))
                ids, rel = csv_rel(BASE / ("base_relaxed_sessions_%s.csv" % span), Xh, Xn)
                assert ids == [m[0] for m in metas], "row order differs from the base CSV"
                report["gate"]["csv_rel_vs_base_%s" % span] = rel
            p = out / ("session_%dms_%s.csv" % (ms, span))
            write_csv(p, metas, Xh, Xn)
            report["outputs_sha256"][p.name] = sha256(p)
    for ms in MS:
        r = 500 // ms
        Nw = np.stack([per[i]["N"][ms][pi[i] * r:(pi[i] + 160) * r] for i in range(len(PS))])
        p = out / ("session_windows_%dms.npz" % ms)
        np.savez_compressed(p, N=Nw, net_signals=np.asarray(NET_SIGNALS),
                            execution_ids=np.asarray([m[0] for m in metas]),
                            labels=np.asarray([CS.label(s) for s in PS]), groups=np.asarray([s["group"] for s in PS]),
                            strata=np.asarray([s["stratum"] for s in PS]))
        report["outputs_sha256"][p.name] = sha256(p)
    g = report["gate"]
    ok = (g["sessions_windows_equal"] == len(PS) and g["summary_rel_vs_build_base_20s"] == 0.0
          and g["summary_rel_vs_build_base_80s"] == 0.0 and g["csv_rel_vs_base_20s"] < 1e-8
          and g["csv_rel_vs_base_80s"] < 1e-8 and all(v == 0.0 for v in report["nesting_max_abs"].values()))
    g["passed"] = bool(ok)
    report["inputs_sha256"] = {
        "build_base.py": sha256(SL / "build_base.py"), "with_runs.py": sha256(SL / "with_runs.py"),
        "analyze_session_lab.py": sha256(SL / "analyze_session_lab.py"),
        "compare_session_lab.py": sha256(SL / "compare_session_lab.py"),
        "switch_model.py": sha256(Path(sm.__file__)), "build_session_short.py": sha256(Path(__file__)),
        "base_relaxed_sessions_20s.csv": sha256(BASE / "base_relaxed_sessions_20s.csv"),
        "base_relaxed_sessions_80s.csv": sha256(BASE / "base_relaxed_sessions_80s.csv")}
    report["seconds"] = round(time.time() - t0, 1)
    (out / "session_build.json").write_text(json.dumps(report, indent=1, default=str))
    print("[session] gate %s: windows equal %d/%d; summaries vs build_base 20s %.1e 80s %.1e; vs base CSVs 20s %.1e "
          "80s %.1e; nesting %s; composition %s; %.0f s" % (
              "PASSED" if ok else "FAILED", g["sessions_windows_equal"], len(PS), g["summary_rel_vs_build_base_20s"],
              g["summary_rel_vs_build_base_80s"], g["csv_rel_vs_base_20s"], g["csv_rel_vs_base_80s"],
              report["nesting_max_abs"], report["composition"], report["seconds"]))
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
