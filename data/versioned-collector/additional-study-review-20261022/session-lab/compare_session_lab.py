#!/usr/bin/env python3
"""Session lab vs the paper's dataset (offline). Reads the accepted sessions of one or more attempts
(sessions/<sid>/windows.json from analyze_session_lab.py --features, and analysis.json) and reports:

 A  behaviour of each dataset malware sample: its dataset run (20 s, collector visible in the guest, the Sink
    answering only itself) vs its session (hidden monitor, sinkhole answering every connection, injected into
    background activity) vs Triage's internet sandbox (sample-intel-20261113/triage_network-20261115.csv);
 B  benign tasks re-run in sessions: the injected program's first 20 s vs the same task's dataset row;
 C  detection on per-program rows (the injected program alone, 20 s from its injection, as long as a dataset run;
    also 80 s): C1 the paper's detectors trained on the 240 dataset rows applied to the session rows; C2 grouped
    cross-validation within the session rows (families / projects / programs held out, 10 fold assignments);
 D  detection per 10-s machine window (LID-DS-like): both cgroups' host rows and all of the guest's traffic, the
    window starting 2 s before the injection; the same session's earlier window as a normal window; grouped CV;
 E  the lab cue: does "a connection of the program was left unanswered" still single out malware?
Detectors and protocol as the paper's (committee-eval common.py: RF500 balanced seed 42, stacked logistic fusion
with inner grouped folds, threshold 0.5). Post hoc; no model is promoted and nothing is merged with the dataset.

  /usr/bin/python3 compare_session_lab.py <attempt> [<attempt> ...] --out <dir>
"""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import mannwhitneyu, spearmanr

HERE = Path(__file__).resolve().parent
ASR = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ASR / "committee-eval-20261113"))
import common as C               # noqa: E402
import run_session_lab as lab    # noqa: E402

TRIAGE = ASR / "sample-intel-20261113" / "triage_network-20261115.csv"
SPANS = {"20s": 40, "80s": 160}


def accepted(sdir):
    recheck = sdir / "checks-recheck.json"
    if recheck.is_file():
        return lab.load(recheck)["recheck"]["accepted"]
    rec = lab.load(sdir / "result.json")
    return rec.get("status") == "accepted"


def session_class(flows, span=""):
    n, a = flows["flows" + span], flows["answered" + span]
    if not n:
        return "silent"
    if a == n:
        return "all_answered"
    return "none_answered" if a == 0 else "some_unanswered"


def program_ran(sdir):
    """Did the injected program start? True if its cgroup made a call under a name other than bash (the waiting
    shell and the dataset's launch wrapper are bash; a program that never ran, or crashed before its first call,
    leaves only bash rows). None if the monitor log is missing."""
    f = sdir / "guest" / "host-b.log"
    if not f.is_file():
        return None
    for line in f.read_bytes().decode(errors="replace").split("\n"):   # "\n" only, as analyze_session_lab.log_lines
        if not line or line.startswith(("====", "COMM", "HOSTMON")):
            continue
        if line.split(",", 1)[0].strip('"') != "bash":
            return True
    return False


def load_sessions(attempts):
    out, skipped = [], []
    for att in attempts:
        protocol = lab.load(att / "protocol.json")
        reports = {r["sid"]: r for r in lab.load(att / "analysis.json")["sessions"]}
        for s in protocol["sessions"]:
            sdir = att / "sessions" / s["sid"]
            if not (sdir / "result.json").is_file():
                continue
            if not accepted(sdir) or not (sdir / "windows.json").is_file() or s["sid"] not in reports:
                skipped.append((att.name, s["sid"], s["kind"], s["name"]))
                continue
            w = lab.load(sdir / "windows.json")
            out.append(dict(s, attempt=att.name, report=reports[s["sid"]], W=w["features"],
                            program_ran=program_ran(sdir)))
    return out, skipped


def label(s):
    return 1 if s["kind"] in ("malware", "attack") else 0


def group(s):
    if s["kind"] == "malware":
        return "family::" + s["family"]
    if s["kind"] == "benign" and s.get("project"):
        return "project::" + s["project"]
    if s["kind"] == "attack":
        return "attack::" + s["name"]
    return "%s::%s" % (s["kind"], s["name"])


def window_matrix(sessions, view, part, start, n, signals):
    """(sessions, n, signals) from the per-window features of one view (machine/program) and part (host/net)."""
    out = np.zeros((len(sessions), n, len(signals)))
    for i, (s, a) in enumerate(zip(sessions, start)):
        ws = s["W"][view][part][a:a + n]
        for j, w in enumerate(ws):
            out[i, j] = [float(w[k]) for k in signals]
    return out


def recall_at_fa(y, prob, fa):
    """Recall with the threshold that lets the given share of the negatives through (as in the LID-DS analysis)."""
    neg = np.sort(prob[y == 0])
    thr = neg[min(len(neg) - 1, int(np.ceil((1 - fa) * len(neg))) - 1)] if len(neg) else 1.0
    return float((prob[y == 1] > thr).mean())


def score(y, P):
    per = {d: [C.metrics(y, P[d][k]) for k in range(P[d].shape[0])] for d in P}
    out = {d: {"ba_mean": float(np.mean([m["balanced_accuracy"] for m in v])),
               "ba_sd": float(np.std([m["balanced_accuracy"] for m in v], ddof=1)) if len(v) > 1 else 0.0,
               "auc_mean": float(np.nanmean([m["auc"] for m in v])),
               "recall_mean": float(np.mean([m["recall"] for m in v])),
               "specificity_mean": float(np.mean([m["specificity"] for m in v]))} for d, v in per.items()}
    for d in P:
        for fa in (0.05, 0.10):
            out[d]["recall_at_%dfa" % int(fa * 100)] = float(np.mean([recall_at_fa(y, P[d][k], fa)
                                                                      for k in range(P[d].shape[0])]))
    return out


def grouped_cv_P(Xh, Xn, y, g, detectors=C.DETECTORS):
    """(scores, OOF probabilities) of grouped 5-fold CV over the 10 fold assignments; (skip note, None) if too few."""
    groups = (len(set(g[y == 1])), len(set(g[y == 0])))
    if len(set(y)) < 2 or min(groups) < 5 or min((y == 1).sum(), (y == 0).sum()) < 10:
        return {"skipped": "too few for grouped 5-fold CV (%d malicious and %d benign groups, %d and %d rows)" % (
            groups[0], groups[1], (y == 1).sum(), (y == 0).sum())}, None
    try:
        P, _ = C.cv_all(Xh, Xn, y, g, detectors=detectors, jobs=10)
    except ValueError as error:      # a training fold too small for the stacked detector's inner folds
        return {"skipped": "split failed: %s" % error}, None
    return score(y, P), P


def grouped_cv(Xh, Xn, y, g):
    return grouped_cv_P(Xh, Xn, y, g)[0]


# Added after the interim look (DESIGN.md "Evaluation": baselines for injection time, activity, lifetime and batch;
# seen vs unseen families); the prologue-signal check is a post hoc diagnostic (the launch paths differ, see REPORT).
PROLOGUE_SIGNALS = ("max_run_length", "first50_unique", "first100_unique")


def mode_of(s):
    if s.get("mode"):
        return s["mode"]
    name = s.get("archive") or ""
    for m in ("native_amd64_dynamic", "native_amd64_static", "native_i386_static"):
        if name.startswith(m.replace("native_", "")) or ("-" + m + "-") in name or name.startswith("null-" + m):
            return m
    return "native_amd64_static"     # the lab's own tools (webfetch, netpoll) are static amd64 builds


def baseline_cv(x, y, g):
    X = np.asarray(x, dtype=float).reshape(len(y), -1)
    return grouped_cv_P(X, X, y, g, detectors=("host",))[0].get("host", {"skipped": "too few"})


def noise_reference(y, g, draws=20, seed=20261116):
    """Chance range of a one-feature baseline under the same folds: BA of random uniform features."""
    rng = np.random.default_rng(seed)
    bas = []
    for _ in range(draws):
        r = baseline_cv(rng.uniform(size=len(y)), y, g)
        if "ba_mean" in r:
            bas.append(r["ba_mean"])
    if not bas:
        return {"skipped": "too few"}
    return {"draws": len(bas), "mean": float(np.mean(bas)), "p95": float(np.percentile(bas, 95)),
            "max": float(np.max(bas))}


def paired(y, P, ref="host"):
    """Per fold assignment: BA of each detector minus the reference detector's."""
    ba = {d: np.asarray([C.metrics(y, P[d][k])["balanced_accuracy"] for k in range(P[d].shape[0])]) for d in P}
    return {"%s_minus_%s" % (d, ref): {"mean": float((ba[d] - ba[ref]).mean()),
                                       "sd": float((ba[d] - ba[ref]).std(ddof=1)),
                                       "positive": int(((ba[d] - ba[ref]) > 0).sum()),
                                       "assignments": int(len(ba[d]))} for d in P if d != ref}


def by_group(y, g, P):
    """Share of a group's rows flagged at 0.5, mean over the fold assignments, per detector."""
    out = {}
    for grp in sorted(set(g)):
        idx = np.where(g == grp)[0]
        out[grp] = {"label": int(y[idx[0]]), "rows": int(len(idx)),
                    **{d: float((P[d][:, idx] >= 0.5).mean()) for d in P}}
    return out


def program_baselines(ps, pi, n, attempts):
    act = window_matrix(ps, "program", "host", pi, n, ["host_total_syscalls_total"])[:, :, 0]
    modes = sorted({mode_of(s) for s in ps})
    return {"activity": np.log1p(act.sum(1)),
            "lifetime": (act > 0).sum(1),
            "injection_time": np.asarray([s["t_inject_s"] for s in ps]),
            "batch": np.asarray([attempts.index(s["attempt"]) for s in ps]),
            "mode": np.asarray([modes.index(mode_of(s)) for s in ps])}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("attempts", nargs="+")
    p.add_argument("--out", required=True)
    a = p.parse_args()
    attempts = [Path(x).resolve() for x in a.attempts]
    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    sessions, skipped = load_sessions(attempts)
    rows, host_cols, net_cols = C.load()
    hs, ns = C.signals(host_cols), C.signals(net_cols)
    by_sha = {r["sha256"]: r for r in rows if r["sha256"]}
    dirs = C.run_dirs(rows)
    by_task = {}
    for r, d in zip(rows, dirs):
        if r["category"] == "benign" and d is not None:
            by_task[Path(str(d)).name.split("/")[-1]] = r
    triage = {r["sha256"]: r for r in csv.DictReader(open(TRIAGE))}
    result = {"attempts": [x.name for x in attempts], "sessions": len(sessions), "skipped": skipped,
              "kinds": dict(Counter(s["kind"] for s in sessions))}

    # A: behaviour of the dataset's malware, dataset run vs session vs Triage
    inj = [int(s["t_inject_s"] // 0.5) for s in sessions]
    A = []
    for s, iw in zip(sessions, inj):
        if s["kind"] != "malware":
            continue
        d, t = by_sha.get(s["sha256"]), triage.get(s["sha256"], {})
        f = s["report"]["injected_flows"]
        pw = s["W"]["program"]["net"][iw:iw + 40]
        rho = None
        if d:
            vec = np.concatenate([C.summarize(window_matrix([s], "program", "host", [iw], 40, hs))[0],
                                  C.summarize(window_matrix([s], "program", "net", [iw], 40, ns))[0]])
            ref = np.asarray([float(d[c]) for c in host_cols + net_cols])
            rho = float(spearmanr(vec, ref).correlation)
        A.append({"sha256": s["sha256"], "family": s["family"], "attempt": s["attempt"], "sid": s["sid"],
                  "dataset_split": d["split"] if d else None,
                  "dataset_packets_20s": float(d["net_pkts_total_delta__sum"]) if d else None,
                  "dataset_host_calls_20s": float(d["host_total_syscalls_total__sum"]) if d else None,
                  "dataset_lab_class": t.get("lab_class"), "triage_class": t.get("triage_class"),
                  "session_class": session_class(f), "session_class_20s": session_class(f, "_20s"),
                  "session_flows": f["flows"], "session_answered": f["answered"], "session_flows_20s": f["flows_20s"],
                  "session_dns_relayed": f.get("dns_relayed"),
                  "session_remotes": f["remote_count"], "session_ports": f["ports"],
                  "session_first_contact_s": f["first_contact_s"],
                  "session_packets_20s": float(sum(w["net_pkts_total_delta"] for w in pw)),
                  "spearman_235_vs_dataset": rho, "program_ran": s["program_ran"],
                  "session_host_calls_20s": float(sum(w["host_total_syscalls_total"]
                                                      for w in s["W"]["program"]["host"][iw:iw + 40]))})
    crosstab = Counter((x["dataset_lab_class"], x["session_class"]) for x in A)
    crosstab20 = Counter((x["dataset_lab_class"], x["session_class_20s"]) for x in A)
    result["A_behaviour"] = {"samples": A, "dataset_lab_vs_session": {"%s -> %s" % k: v for k, v in crosstab.items()},
                             "dataset_lab_vs_session_20s": {"%s -> %s" % k: v for k, v in crosstab20.items()},
                             "triage_vs_session": {"%s -> %s" % k: v for k, v in
                                                   Counter((x["triage_class"], x["session_class"]) for x in A).items()},
                             "silent_in_dataset_network_in_session": sum(
                                 1 for x in A if x["dataset_lab_class"] == "silent" and x["session_class"] != "silent"),
                             "silent_in_dataset": sum(1 for x in A if x["dataset_lab_class"] == "silent")}

    # B: benign tasks, session program rows vs the dataset rows of the same task
    B = []
    for s, iw in zip(sessions, inj):
        if s["kind"] != "benign" or not s.get("archive"):
            continue
        d = by_task.get(s["archive"][:-4]) or by_task.get(s["archive"])
        if not d:
            continue
        Wh = window_matrix([s], "program", "host", [iw], 40, hs)
        Wn = window_matrix([s], "program", "net", [iw], 40, ns)
        vec = np.concatenate([C.summarize(Wh)[0], C.summarize(Wn)[0]])
        ref = np.asarray([float(d[c]) for c in host_cols + net_cols])
        rho = spearmanr(vec, ref).correlation
        B.append({"task": s["archive"], "project": s["project"], "spearman_235": float(rho),
                  "host_calls_session": float(vec[0 * 5 + 2]), "host_calls_dataset": float(ref[2]),
                  "packets_session": float(sum(w["net_pkts_total_delta"] for w in s["W"]["program"]["net"][iw:iw + 40])),
                  "packets_dataset": float(d["net_pkts_total_delta__sum"])})
    result["B_benign_agreement"] = {"tasks": B, "median_spearman": float(np.median([b["spearman_235"] for b in B]))
                                    if B else None}

    # Eligibility as in the dataset (which required the target's exec to be observed): the injected program must
    # have started (program_ran). C, D and E use the eligible sessions; A above keeps every session.
    result["not_started"] = [[s["attempt"], s["sid"], s["kind"], s["name"]] for s in sessions
                             if s["kind"] != "none" and s["program_ran"] is False]
    all_prog = [(s, iw) for s, iw in zip(sessions, inj) if s["kind"] != "none"]
    keep = [i for i, s in enumerate(sessions) if s["kind"] == "none" or s["program_ran"] is not False]
    sessions, inj = [sessions[i] for i in keep], [inj[i] for i in keep]

    # C: per-program rows (sessions with an injected program)
    prog = [(s, iw) for s, iw in zip(sessions, inj) if s["kind"] != "none"]
    C_out = {}
    if prog:
        ps, pi = [s for s, _ in prog], [iw for _, iw in prog]
        y = np.asarray([label(s) for s in ps])
        g = np.asarray([group(s) for s in ps])
        ti = np.asarray([s["t_inject_s"] for s in ps], dtype=float)
        result["C_injection_time_by_class"] = {          # a check that the seeded times carry no label
            "malicious_median_s": float(np.median(ti[y == 1])), "benign_median_s": float(np.median(ti[y == 0])),
            "mannwhitney_p": float(mannwhitneyu(ti[y == 1], ti[y == 0], alternative="two-sided").pvalue)}
        Xd_h, Xd_n, yd, gd = C.matrix(rows, host_cols), C.matrix(rows, net_cols), C.labels(rows), C.groups_published(rows)
        for span, n in SPANS.items():
            Xh = C.summarize(window_matrix(ps, "program", "host", pi, n, hs))
            Xn = C.summarize(window_matrix(ps, "program", "net", pi, n, ns))
            entry = {"n": int(len(y)), "malicious": int(y.sum())}
            if span == "20s":       # C1: the paper's detectors (trained on the 240 dataset rows), applied here
                XH, XN = np.vstack([Xd_h, Xh]), np.vstack([Xd_n, Xn])
                YY, GG = np.concatenate([yd, y]), np.concatenate([gd, g])
                tr, te = np.arange(len(yd)), np.arange(len(yd), len(yd) + len(y))
                probs = C.fit_predict(XH, XN, YY, GG, tr, te)
                entry["C1_transfer"] = {d: C.metrics(y, pr) for d, pr in probs.items()}
                entry["C1_flagged_by_kind"] = {d: {k: float(np.mean([pr[i] >= 0.5 for i, s in enumerate(ps)
                                                                     if s["kind"] == k]))
                                                   for k in sorted({s["kind"] for s in ps})} for d, pr in probs.items()}
                # post hoc: the same transfer without the six host columns of the three start-up-dominated signals
                hs_k = [x for x in hs if not any(p in x for p in PROLOGUE_SIGNALS)]
                hc_k = [c for c in host_cols if c.rsplit("__", 1)[0] in hs_k]
                Xh_k = C.summarize(window_matrix(ps, "program", "host", pi, n, hs_k))
                probs_k = C.fit_predict(np.vstack([C.matrix(rows, hc_k), Xh_k]), XN, YY, GG, tr, te)
                entry["C1_transfer_without_prologue_signals"] = {
                    "signals_dropped": [x for x in hs if x not in hs_k],
                    "metrics": {d: C.metrics(y, pr) for d, pr in probs_k.items()},
                    "flagged_by_kind": {d: {k: float(np.mean([pr[i] >= 0.5 for i, s in enumerate(ps)
                                                              if s["kind"] == k]))
                                            for k in sorted({s["kind"] for s in ps})} for d, pr in probs_k.items()}}
                launch = {}
                for x in ("host_max_run_length_max__max", "host_first50_unique_mean__max",
                          "host_first100_unique_mean__max"):
                    j = host_cols.index(x)
                    launch[x] = {"dataset_min_median_max": [float(v) for v in np.percentile(Xd_h[:, j], [0, 50, 100])],
                                 "sessions_min_median_max": [float(v) for v in np.percentile(Xh[:, j], [0, 50, 100])]}
                entry["launch_signature"] = launch
            cv, P = grouped_cv_P(Xh, Xn, y, g)
            entry["C2_grouped_cv"] = cv
            if P is not None:
                entry["C2_paired"] = paired(y, P)
                entry["C2_by_group"] = by_group(y, g, P)
            entry["C2_baselines"] = {k: baseline_cv(v, y, g) for k, v in
                                     program_baselines(ps, pi, n, result["attempts"]).items()}
            entry["C2_baseline_noise_reference"] = noise_reference(y, g)
            entry["C2_seen_families"] = grouped_cv(Xh, Xn, y, np.asarray(["row%d" % i for i in range(len(y))]))
            if span == "20s":
                with open(out_dir / "program_rows_20s.csv", "w", newline="") as fh:
                    wr = csv.writer(fh)
                    wr.writerow(["attempt", "sid", "kind", "name", "group", "label", "mode", "t_inject_s"]
                                + host_cols + net_cols)
                    for i, s in enumerate(ps):
                        wr.writerow([s["attempt"], s["sid"], s["kind"], s["name"], g[i], int(y[i]), mode_of(s),
                                     s["t_inject_s"]] + ["%.9g" % v for v in Xh[i]] + ["%.9g" % v for v in Xn[i]])
            C_out[span] = entry
    result["C_per_program"] = C_out
    if len(all_prog) != len(prog):       # sensitivity: the same grouped CV with the programs that never started
        ps_a, pi_a = [s for s, _ in all_prog], [iw for _, iw in all_prog]
        y_a, g_a = np.asarray([label(s) for s in ps_a]), np.asarray([group(s) for s in ps_a])
        result["C_all_rows_20s"] = {"n": int(len(y_a)), "malicious": int(y_a.sum()), "grouped_cv": grouped_cv(
            C.summarize(window_matrix(ps_a, "program", "host", pi_a, 40, hs)),
            C.summarize(window_matrix(ps_a, "program", "net", pi_a, 40, ns)), y_a, g_a)}

    # D: machine windows (both cgroups, all traffic) around the injection, and the same session's window before
    #    it as a normal window: 10 s starting 2 s before the injection (LID-DS's layout), and 30 s from the injection
    def machine_eval(ms, mstart, my, mg, n):
        Xh = C.summarize(window_matrix(ms, "machine", "host", mstart, n, hs))
        Xn = C.summarize(window_matrix(ms, "machine", "net", mstart, n, ns))
        y, g = np.asarray(my), np.asarray(mg)
        act = np.log1p(Xh[:, 2])
        cv, P = grouped_cv_P(Xh, Xn, y, g)
        D = {"n": int(len(y)), "malicious": int(y.sum()), "grouped_cv": cv}
        if "skipped" not in D["grouped_cv"]:
            P1, _ = C.cv_all(act[:, None], act[:, None], y, g, detectors=("host",), jobs=10)
            D["activity_baseline"] = score(y, P1)["host"]
            D["position_baseline"] = baseline_cv(np.asarray(mstart), y, g)     # where in the session the window is
            D["baseline_noise_reference"] = noise_reference(y, g, draws=10)
            D["paired"] = paired(y, P)
            D["seen_families"] = grouped_cv(Xh, Xn, y, np.asarray(["row%d" % i for i in range(len(y))]))
        return D

    for name, (offset, n, before) in {"10s": (-4, 20, -44), "30s": (0, 60, -64)}.items():
        ms, mstart, my, mg = [], [], [], []
        for s, iw in zip(sessions, inj):
            ms += [s, s]
            mstart += [iw + offset, iw + before]
            my += [label(s), 0]
            mg += [group(s), group(s)]
        if not ms:
            continue
        key = "D_machine_windows" if name == "10s" else "D_machine_windows_30s"
        result[key] = machine_eval(ms, mstart, my, mg, n)
        # added after the interim look (the position baseline scored 0.60-0.67): only the window at the injection
        # time of every session, so malicious and normal windows have the same distribution of positions (the
        # injection times of all sessions come from the same seeded 40-100 s draw)
        result[key + "_matched"] = machine_eval(list(sessions), [iw + offset for iw in inj],
                                                [label(s) for s in sessions], [group(s) for s in sessions], n)

    # E: the lab cue on per-program rows
    if prog:
        ps = [s for s, _ in prog]
        y = np.asarray([label(s) for s in ps])
        unans = np.asarray([int(s["report"]["injected_flows"]["flows"] > s["report"]["injected_flows"]["answered"])
                            for s in ps])
        result["E_lab_cue"] = {"rule": "flag the program if any of its connections got no reply",
                               "metrics": C.metrics(y, unans.astype(float)),
                               "flagged_by_kind": {k: float(np.mean([u for u, s in zip(unans, ps) if s["kind"] == k]))
                                                   for k in sorted({s["kind"] for s in ps})}}
    C.write_json(out_dir / "comparison.json", result)
    print(json.dumps({k: v for k, v in result.items() if k not in ("skipped",)}, indent=1, default=str)[:6000])


if __name__ == "__main__":
    main()
