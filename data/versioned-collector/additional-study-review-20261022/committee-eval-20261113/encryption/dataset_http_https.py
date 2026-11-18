"""Encryption check, part 1: the dataset's benign network clients over HTTP vs HTTPS (offline, read-only).

Committee request: "an explicit encrypted-traffic evaluation ... showing the features don't shift". This part uses
captures that already exist; no VM, no new runs, nothing in the collections is executed or modified.

Runs. The release dataset (features.csv, 240 rows) holds the revision5 collection's network-active benign clients.
The same benign binaries (identical SHA-256, read from the payload zips in memory) with the same arguments were also
run, with the same .21 runner and settings from the same quiet guest image, in four earlier benign-capable phases:
the superseded revision5 attempt's benign-only preflight, the v21 collection and its two benign-only preflights
(2026-10-24/25, before the Sink outage of 2026-11-06). Those runs are used only as repeats of the same task; they
are not added to any training set.

Contrasts (per execution mode, same binary):
  transport   curl GET http://10.0.0.1/  vs  curl -k GET https://10.0.0.1/   <- the paired encryption test
  request     curl GET /  vs  POST /submit, GET /headers -D, GET /index.html (all cleartext HTTP)
  options     curl GET / -s  vs  the same GET without -s and --max-time 4 (amd64 dynamic)
  program     curl GET /  vs  wget GET /                                  (both cleartext HTTP)
  url         wget GET /  vs  wget GET /data
  tls-option  openssl s_client with SNI  vs  -tls1_3                      (both TLS)
  port        telnet to port 80  vs  443 (TCP connect only, no TLS)       (control: ports are not features)
For every contrast: per column (90 host + 145 network five-statistic summaries of the 40 windows) the mean change,
the pooled standard deviation between repeats of the same task, whether the two sets of repeats are completely
separated, and the change in units of the column's standard deviation over the 240 dataset rows; per block the
Euclidean distance between the two means in those units, the mean distance between repeats, and an exact
permutation p-value over all relabelings of the runs (when each side has >= 3 runs).

Detectors (paper definitions, common.fit_predict). Dataset rows: the cached out-of-fold probabilities of the Table V
protocol (10 fold assignments; cache/cv_published_k40.npz, checked to reproduce host .784 / network .756 / stacked
.823 first). Repeats: scored by the same fold models (for each assignment, the model trained on the folds that hold
out the program's group), refit here; the refit must reproduce the cached probabilities of the dataset rows of those
folds exactly. Decision changes: in each assignment, HTTP-vs-HTTPS pairs of runs vs pairs of repeats of one task.

    nice -n 19 /usr/bin/python3 dataset_http_https.py [--jobs 4]
"""
import argparse
import csv
import glob
import hashlib
import json
import sys
import time
import zipfile
from collections import Counter, defaultdict
from itertools import combinations
from multiprocessing import Pool
from pathlib import Path

import numpy as np
import sklearn
from sklearn.model_selection import StratifiedGroupKFold

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import common as C  # noqa: E402
sys.path.insert(0, str(HERE))
import contrast as K  # noqa: E402
import wire  # noqa: E402

STUDY = C.STUDY
RUNNER = "4933ff5c9c56bd097ce565d14a7173bd281dd124aca43d1df0dbe76315e64b9c"
SCHEMA = "2026-10-24.21"
SOURCES = [  # tag, attempt, runs directory inside it
    ("rev5", STUDY / "revision5-collection/20261025T100025568989Z", "runs"),
    ("rev5-pre", STUDY / "revision5-collection/20261025T080759917415Z", "phases/preflight-benign/runs"),
    ("v21", STUDY / "v21-collection/20261024T194347772138Z", "runs"),
    ("v21-pre2", STUDY / "v21-collection/20261024T194347772138Z", "phases/preflight-benign/runs"),
    ("v21-pre1", STUDY / "v21-collection/20261024T175120095850Z", "phases/preflight-benign/runs"),
]
GROUP = {"curl": "benign_project::curl", "wget": "benign_project::wget", "openssl": "benign_project::openssl",
         "telnet": "benign_project::inetutils"}
# exact argument strings -> (task id, intended transport, description)
TASKS = {
    "--noproxy * --max-time 6 --fail -s -o http.out http://10.0.0.1/": ("curl_get_root_http", "http", "curl GET / over HTTP"),
    "--noproxy * --max-time 6 -sk -o tls.out https://10.0.0.1/": ("curl_get_root_https", "https", "curl -k GET / over HTTPS"),
    "--noproxy * --max-time 6 -s -o post.out -d probe=1 http://10.0.0.1/submit": ("curl_post_submit_http", "http", "curl POST /submit over HTTP"),
    "--noproxy * --max-time 6 -s -o hdr.out -D hdr.txt http://10.0.0.1/headers": ("curl_get_headers_http", "http", "curl GET /headers -D over HTTP"),
    "--noproxy * --max-time 6 --fail -s -o root.out http://10.0.0.1/index.html": ("curl_get_index_http", "http", "curl GET /index.html over HTTP"),
    "--noproxy * --max-time 4 --fail --output http-response.txt http://10.0.0.1/": ("curl_get_root_http_meter", "http", "curl GET / over HTTP, progress meter on, --max-time 4"),
    "--no-proxy --timeout=6 --tries=1 -O wget.out http://10.0.0.1/": ("wget_get_root_http", "http", "wget GET / over HTTP"),
    "--no-proxy --timeout=6 --tries=1 -O wget2.out http://10.0.0.1/data": ("wget_get_data_http", "http", "wget GET /data over HTTP"),
    "--no-proxy --timeout=6 --tries=1 -O wget3.out http://10.0.0.1/status": ("wget_get_status_http", "http", "wget GET /status over HTTP"),
    "--no-proxy --timeout=4 --tries=1 --output-document=http-response.txt http://10.0.0.1/": ("wget_get_root_http_t4", "http", "wget GET / over HTTP, --timeout=4"),
    "s_client -connect 10.0.0.1:443 -servername sink.local": ("openssl_sclient_sni", "tls", "openssl s_client with SNI"),
    "s_client -connect 10.0.0.1:443 -tls1_3": ("openssl_sclient_tls13", "tls", "openssl s_client -tls1_3"),
    "s_client -connect 10.0.0.1:443 -no_ign_eof": ("openssl_sclient_noigneof", "tls", "openssl s_client -no_ign_eof"),
    "-E 10.0.0.1 80": ("telnet_80", "tcp", "telnet to port 80"),
    "-E 10.0.0.1 443": ("telnet_443", "tcp", "telnet to port 443"),
}
MODES = ("amd64_dynamic", "amd64_static", "i386_static")
# contrast name -> (task A, task B, what differs)
CONTRASTS = [
    ("transport", "curl_get_root_http", "curl_get_root_https", "HTTP -> HTTPS (TLS), same curl binary and request"),
    ("request:post", "curl_get_root_http", "curl_post_submit_http", "GET / -> POST /submit, cleartext"),
    ("request:headers", "curl_get_root_http", "curl_get_headers_http", "GET / -> GET /headers -D, cleartext"),
    ("request:index", "curl_get_root_http", "curl_get_index_http", "GET / -> GET /index.html, cleartext"),
    ("options", "curl_get_root_http", "curl_get_root_http_meter", "same GET /, curl -s off and --max-time 4"),
    ("program", "curl_get_root_http", "wget_get_root_http", "curl -> wget, same GET / cleartext"),
    ("url", "wget_get_root_http", "wget_get_data_http", "wget GET / -> GET /data, cleartext"),
    ("tls-option", "openssl_sclient_sni", "openssl_sclient_tls13", "openssl s_client SNI -> -tls1_3, both TLS"),
    ("port", "telnet_80", "telnet_443", "telnet port 80 -> 443, TCP connect only"),
]
D = {}  # worker data (fork)


def member_sha(zip_path):
    """SHA-256 of the single ELF member of a benign transport zip, read in memory (never written or run)."""
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        assert len(infos) == 1 and not infos[0].flag_bits & 1, zip_path
        return hashlib.sha256(z.read(infos[0])).hexdigest()


def inventory(rows, dirs, hs, ns):
    row_of = {Path(d).resolve(): i for i, d in enumerate(dirs)}
    runs = []
    for tag, att, sub in SOURCES:
        cases = {c["sample"]: c for c in json.load(open(att / "payload/cases.json"))}
        for s, case in sorted(cases.items()):
            if case["label"] != "benign" or case.get("program") not in GROUP:
                continue
            outs = glob.glob(str(att / sub / s / "output" / "run_*"))
            assert len(outs) == 1, (tag, s)
            out = Path(outs[0])
            meta = json.load(open(out / "run.json"))
            args = " ".join(meta["sample_arguments"])
            if "10.0.0.1" not in args:
                continue  # openssl dgst on a local file
            assert json.load(open(att / "payload/arguments" / (s + ".json"))) == meta["sample_arguments"], s
            task, transport, desc = TASKS[args]
            assert meta["malware_runner_sha256"] == RUNNER and meta["telemetry_schema_version"] == SCHEMA, s
            assert meta["collection_quality_status"] == "accepted", s
            assert meta["target_exec"]["status"] == "observed", s
            assert meta["ebpf_lost_event_count"] == 0 and meta["packet_capture_counter_discrepancy"] == 0, s
            assert meta["timeout_seconds"] == 20.0 and meta["window_seconds"] == 0.5, s
            tel = list(csv.DictReader(open(out / "telemetry.csv", newline="", encoding="utf-8-sig")))
            assert len(tel) == 40, s
            H = np.array([[float(x[k]) for k in hs] for x in tel])
            N = np.array([[float(x[k]) for k in ns] for x in tel])
            mode = case["mode"].removeprefix("native_")
            assert mode in MODES, case["mode"]
            run_dir = (att / sub / s).resolve()
            ds = row_of.get(run_dir) if tag == "rev5" else None
            w = wire.summarize(out / "packet_capture.pcap", meta["sample_started_wall_us"], 40)
            assert w["ipv4_tcp_udp_frames"] == int(N[:, ns.index("net_pkts_total_delta")].sum()), s
            assert w["ipv4_tcp_udp_frame_bytes"] == int(N[:, ns.index("net_bytes_total_delta")].sum()), s
            sc = wire.target_syscalls(out, case["program"], mode == "i386_static")
            runs.append({"source": tag, "sample": s, "program": case["program"], "mode": mode, "task": task,
                         "transport_intended": transport, "task_description": desc, "arguments": args,
                         "binary_sha256": member_sha(att / "payload/samples" / s),
                         "dataset_row": ds, "execution_id": rows[ds]["execution_id"] if ds is not None else None,
                         "run_dir": str(out), "started_at_utc": meta["started_at_utc"],
                         "return_code": meta["return_code"], "wire": w,
                         "target_syscalls": dict(sc.most_common()), "target_syscalls_total": sum(sc.values()),
                         "H": H, "N": N})
    return runs


# ------------------------------------------------------------------------------------------- detectors
def refit_job(args):
    si, f, tr, te = args
    p = C.fit_predict(D["Xh"], D["Xn"], D["y"], D["g"], tr, te)
    return si, f, te, p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=4)
    a = ap.parse_args()
    t0 = time.time()
    assert sklearn.__version__.startswith("1.7"), sklearn.__version__
    rows, hc, nc = C.load()
    Xh_d, Xn_d, y_d, g_d = C.matrix(rows, hc), C.matrix(rows, nc), C.labels(rows), C.groups_published(rows)
    hs, ns = C.signals(hc), C.signals(nc)
    cols = hc + nc

    # gate: cached Table V out-of-fold probabilities
    cache_path = C.CACHE / "cv_published_k40.npz"
    cache = np.load(cache_path)
    assert list(cache["seeds"]) == C.FOLD_SEEDS
    gate = {"cache": str(cache_path), "cache_sha256": hashlib.sha256(cache_path.read_bytes()).hexdigest(),
            "sklearn": sklearn.__version__}
    for d, want in (("host", 0.784), ("network", 0.756), ("stacked", 0.823), ("concat", None)):
        v = np.array([C.metrics(y_d, cache[d][i])["balanced_accuracy"] for i in range(len(C.FOLD_SEEDS))])
        gate["table_v_" + d] = {"mean": float(v.mean()), "sd": float(v.std(ddof=1))}
        if want is not None:
            assert round(v.mean(), 3) == want, (d, v.mean())

    dirs = C.run_dirs(rows)
    runs = inventory(rows, dirs, hs, ns)
    X = np.array([np.concatenate([C.summarize(r["H"][None])[0], C.summarize(r["N"][None])[0]]) for r in runs])
    for r, x in zip(runs, X):  # dataset rows: rebuilt summaries equal features.csv
        if r["dataset_row"] is not None:
            ref = np.concatenate([Xh_d[r["dataset_row"]], Xn_d[r["dataset_row"]]])
            assert np.abs(x - ref).max() <= 1e-9 * max(1.0, np.abs(ref).max()), r["sample"]
    n_ds = sum(r["dataset_row"] is not None for r in runs)
    gate["dataset_rows_in_inventory"] = n_ds
    gate["dataset_rows_rebuilt_equal_features_csv"] = True
    gate["wire_counts_equal_switch_packets_and_bytes"] = len(runs)
    net_ds = [i for i, r in enumerate(rows) if r["category"] == "benign" and "-net-" in r["execution_id"]]
    assert n_ds == len(net_ds) - 4 - 2, n_ds  # ftp x4 and ping x2 are outside the four programs

    sd_pop = np.hstack([Xh_d, Xn_d]).std(0, ddof=1)  # spread of each column over the 240 dataset rows
    Z = np.where(sd_pop > 0, X / np.where(sd_pop > 0, sd_pop, 1), 0.0)
    host_idx, net_idx = np.arange(90), np.arange(90, 235)

    # repeat groups
    def key(r):
        return (r["program"], r["mode"], r["binary_sha256"], r["task"])
    groups = defaultdict(list)
    for i, r in enumerate(runs):
        groups[key(r)].append(i)

    # contrasts
    contrasts, column_rows = [], []
    for name, ta, tb, what in CONTRASTS:
        for mode in MODES:
            pairs = []
            for k, idx in groups.items():
                if k[1] == mode and k[3] == ta:
                    for k2, idx2 in groups.items():
                        if k2[1] == mode and k2[3] == tb and (k2[0] == k[0] or name == "program") and \
                                (k2[2] == k[2] or name == "program"):
                            pairs.append((k, idx, k2, idx2))
            for k, A, k2, B in pairs:
                st = K.stats(X[A], X[B], sd_pop)
                rec = {"contrast": name, "what_differs": what, "mode": mode, "task_a": ta, "task_b": tb,
                       "binary_a": k[2][:16], "binary_b": k2[2][:16],
                       "runs_a": [runs[i]["source"] + ":" + runs[i]["sample"] for i in A],
                       "runs_b": [runs[i]["source"] + ":" + runs[i]["sample"] for i in B],
                       "transport_observed_a": sorted({runs[i]["wire"]["transport_observed"] for i in A}),
                       "transport_observed_b": sorted({runs[i]["wire"]["transport_observed"] for i in B}),
                       "host": K.block_summary(st, host_idx, cols, Z[A], Z[B]),
                       "network": K.block_summary(st, net_idx, cols, Z[A], Z[B])}
                contrasts.append(rec)
                for j, c in enumerate(cols):
                    column_rows.append([name, mode, k[2][:8], c, st["mean_a"][j], st["mean_b"][j], st["delta"][j],
                                        st["rel_change"][j], st["sd_within"][j], bool(st["separated"][j]),
                                        st["z"][j]])
    with open(HERE / "columns_dataset.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["contrast", "mode", "binary_a8", "column", "mean_a", "mean_b", "delta", "rel_change",
                    "sd_within_pooled", "repeats_separated", "delta_in_dataset_sd"])
        w.writerows(column_rows)

    # per-signal view of the paired test (max over windows = the active window of these one-shot clients)
    per_signal = {}
    for mode in MODES:
        A = [i for i, r in enumerate(runs) if r["mode"] == mode and r["task"] == "curl_get_root_http"]
        B = [i for i, r in enumerate(runs) if r["mode"] == mode and r["task"] == "curl_get_root_https"]
        tab = {}
        for blk, sigs, arr in (("host", hs, "H"), ("network", ns, "N")):
            for j, s in enumerate(sigs):
                va = np.array([runs[i][arr][:, j].max() for i in A])
                vb = np.array([runs[i][arr][:, j].max() for i in B])
                sa = np.array([runs[i][arr][:, j].sum() for i in A])
                sb = np.array([runs[i][arr][:, j].sum() for i in B])
                tab[s] = {"http_max": [float(v) for v in va], "https_max": [float(v) for v in vb],
                          "http_sum": [float(v) for v in sa], "https_sum": [float(v) for v in sb]}
        per_signal[mode] = tab

    # detectors: dataset rows from the cache, repeats from refit fold models
    extra = [i for i, r in enumerate(runs) if r["dataset_row"] is None]
    Xh_e, Xn_e = X[extra, :90], X[extra, 90:]
    g_e = np.array([GROUP[runs[i]["program"]] for i in extra])
    D.update(Xh=np.vstack([Xh_d, Xh_e]), Xn=np.vstack([Xn_d, Xn_e]),
             y=np.concatenate([y_d, np.zeros(len(extra), int)]), g=np.concatenate([g_d, g_e]))
    jobs = []
    for si, seed in enumerate(C.FOLD_SEEDS):
        folds = list(StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh_d, y_d, g_d))
        for f, (tr, te) in enumerate(folds):
            assert (cache["folds"][si][te] == f).all()
            inside = set(g_d[te])
            ex = [240 + j for j, gg in enumerate(g_e) if gg in inside]
            if ex:
                jobs.append((si, f, tr, np.concatenate([te, ex])))
    with Pool(a.jobs) as pool:
        res = pool.map(refit_job, jobs, chunksize=1)
    P = {d: np.full((len(C.FOLD_SEEDS), len(runs)), np.nan) for d in C.DETECTORS}
    ds_pos = {r["dataset_row"]: i for i, r in enumerate(runs) if r["dataset_row"] is not None}
    for i, r in enumerate(runs):
        if r["dataset_row"] is not None:
            for d in C.DETECTORS:
                P[d][:, i] = cache[d][:, r["dataset_row"]]
    max_refit_diff = 0.0
    for si, f, te, p in res:
        for d in C.DETECTORS:
            ds_part = te < 240
            max_refit_diff = max(max_refit_diff, float(np.abs(p[d][ds_part] - cache[d][si][te[ds_part]]).max()))
            for t, v in zip(te[~ds_part], p[d][~ds_part]):
                P[d][si, extra[t - 240]] = v
    assert max_refit_diff == 0.0, max_refit_diff
    assert not any(np.isnan(P[d]).any() for d in C.DETECTORS)
    gate["refit_jobs"] = len(jobs)
    gate["refit_reproduces_cached_oof_max_abs_diff"] = max_refit_diff

    for i, r in enumerate(runs):
        r["scores"] = {d: {"prob_by_assignment": [round(float(x), 4) for x in P[d][:, i]],
                           "mean_prob": float(P[d][:, i].mean()), "flagged_assignments": int((P[d][:, i] >= .5).sum())}
                       for d in C.DETECTORS}

    def decisions(A, B):
        """Disagreement between the decisions on two runs scored by the same fold model (same assignment)."""
        out = {}
        for d in C.DETECTORS:
            flag = P[d] >= 0.5
            between = [flag[s, i] != flag[s, j] for s in range(len(C.FOLD_SEEDS)) for i in A for j in B]
            a_only = sum(bool(flag[s, i] and not flag[s, j]) for s in range(len(C.FOLD_SEEDS)) for i in A for j in B)
            b_only = sum(bool(flag[s, j] and not flag[s, i]) for s in range(len(C.FOLD_SEEDS)) for i in A for j in B)
            within = [flag[s, i] != flag[s, j] for s in range(len(C.FOLD_SEEDS)) for G in (A, B)
                      for i, j in combinations(G, 2)]
            dp_b = [abs(P[d][s, i] - P[d][s, j]) for s in range(len(C.FOLD_SEEDS)) for i in A for j in B]
            dp_w = [abs(P[d][s, i] - P[d][s, j]) for s in range(len(C.FOLD_SEEDS)) for G in (A, B)
                    for i, j in combinations(G, 2)]
            out[d] = {"flag_rate_a": float(flag[:, A].mean()), "flag_rate_b": float(flag[:, B].mean()),
                      "mean_prob_a": float(P[d][:, A].mean()), "mean_prob_b": float(P[d][:, B].mean()),
                      "disagree_between": [int(sum(between)), len(between)],
                      "disagree_between_only_a_flagged": int(a_only), "disagree_between_only_b_flagged": int(b_only),
                      "disagree_within_repeats": [int(sum(within)), len(within)],
                      "mean_abs_dprob_between": float(np.mean(dp_b)),
                      "mean_abs_dprob_within": float(np.mean(dp_w)) if dp_w else None}
        return out

    for rec in contrasts:
        idx = {r["source"] + ":" + r["sample"]: i for i, r in enumerate(runs)}
        rec["detectors"] = decisions([idx[x] for x in rec["runs_a"]], [idx[x] for x in rec["runs_b"]])

    # all transport-pair decisions pooled over modes (the paired encryption test)
    pooled = {}
    tp = [c for c in contrasts if c["contrast"] == "transport"]
    for d in C.DETECTORS:
        pooled[d] = {k: [sum(c["detectors"][d][k][0] for c in tp), sum(c["detectors"][d][k][1] for c in tp)]
                     for k in ("disagree_between", "disagree_within_repeats")}
        pooled[d]["only_http_flagged"] = sum(c["detectors"][d]["disagree_between_only_a_flagged"] for c in tp)
        pooled[d]["only_https_flagged"] = sum(c["detectors"][d]["disagree_between_only_b_flagged"] for c in tp)
    by_transport = {}
    for cls in ("http", "https", "tls", "tcp"):
        idx = [i for i, r in enumerate(runs) if r["transport_intended"] == cls]
        by_transport[cls] = {"runs": len(idx), "dataset_rows": sum(runs[i]["dataset_row"] is not None for i in idx),
                             **{d: {"flag_rate": float((P[d][:, idx] >= .5).mean()),
                                    "mean_prob": float(P[d][:, idx].mean())} for d in C.DETECTORS}}
    base = {}
    ben = [i for i, r in enumerate(rows) if r["category"] == "benign"]
    netb = [i for i in ben if "-net-" in rows[i]["execution_id"]]
    for d in C.DETECTORS:
        base[d] = {"benign_105_flag_rate": float((cache[d][:, ben] >= .5).mean()),
                   "network_benign_27_flag_rate": float((cache[d][:, netb] >= .5).mean())}

    out = {"gate": gate, "sources": {t: str(p / s) for t, p, s in SOURCES},
           "n_runs": len(runs), "runs_by_source": dict(Counter(r["source"] for r in runs)),
           "columns": cols,
           "runs": [dict({k: v for k, v in r.items() if k not in ("H", "N")}, features=X[i].tolist())
                    for i, r in enumerate(runs)],
           "contrasts": contrasts, "paired_signals": per_signal,
           "transport_pairs_pooled": pooled, "flag_rate_by_transport_class": by_transport,
           "table_v_oof_flag_rates": base, "elapsed_s": round(time.time() - t0, 1)}
    C.write_json(HERE / "results_dataset.json", out)
    print("runs %d (dataset rows %d), refit jobs %d, refit max diff %g, %.0f s" % (
        len(runs), n_ds, len(jobs), max_refit_diff, time.time() - t0))
    for c in contrasts:
        print("%-16s %-14s %3s/%-3s host: chg %2d sep %2d D %.2f (rep %.2f p %s) | net: chg %3d sep %3d D %.2f (rep %s p %s)"
              % (c["contrast"], c["mode"], len(c["runs_a"]), len(c["runs_b"]), c["host"]["changed"],
                 c["host"]["separated"], c["host"]["distance"]["between_means"],
                 c["host"]["distance"]["mean_within_pair"] or 0,
                 c["host"]["distance"]["perm_p"], c["network"]["changed"], c["network"]["separated"],
                 c["network"]["distance"]["between_means"],
                 "%.2f" % c["network"]["distance"]["mean_within_pair"]
                 if c["network"]["distance"]["mean_within_pair"] is not None else "-",
                 c["network"]["distance"]["perm_p"]))


if __name__ == "__main__":
    main()
