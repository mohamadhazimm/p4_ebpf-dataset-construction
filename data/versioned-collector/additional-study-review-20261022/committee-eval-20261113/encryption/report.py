"""Build results.json (key numbers and verdict) and the tables of README.md from the two part results. Offline.

    /usr/bin/python3 report.py
"""
import hashlib
import json
from string import Template
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
DET = ("host", "network", "concat", "stacked")
MODES = ("amd64_dynamic", "amd64_static", "i386_static")
CLEAN = "without_stray_wireguard"


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def num(x, nd=3):
    if x is None:
        return "-"
    if float(x).is_integer():
        return "%d" % x
    return ("%%.%dg" % nd) % x


def arrow(a, b):
    if a == b:
        return "%s (same)" % num(a)
    if a == 0:
        return "%s → %s" % (num(a), num(b))
    return "%s → %s (%+.0f%%)" % (num(a), num(b), 100.0 * (b - a) / abs(a))


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def frac(p):
    return "%d/%d" % tuple(p)


def main():
    D = json.load(open(HERE / "results_dataset.json"))
    S = json.load(open(HERE / "results_sliver.json"))
    runs = D["runs"]
    ds = {(r["mode"], r["task"]): r for r in runs if r["source"] == "rev5"}
    con = {(c["contrast"], c["mode"]): c for c in D["contrasts"] if c["contrast"] != "port"}
    ports = [c for c in D["contrasts"] if c["contrast"] == "port"]

    # ---------------------------------------------------------------------------- part 1 tables
    t_pairs = []
    for m in MODES:
        a, b = ds[(m, "curl_get_root_http")], ds[(m, "curl_get_root_https")]
        rep = [r for r in runs if r["mode"] == m and r["task"] == "curl_get_root_http"]
        t_pairs.append([m, "`%s` (row %d)" % (a["execution_id"], a["dataset_row"]),
                        "`%s` (row %d)" % (b["execution_id"], b["dataset_row"]), "`%s`" % a["binary_sha256"][:16],
                        "%d + %d" % (len(rep), len([r for r in runs if r["mode"] == m and r["task"] == "curl_get_root_https"])),
                        "%s / %s" % (a["wire"]["transport_observed"], b["wire"]["transport_observed"])])
    t_wire = []
    for k, lab in (("ipv4_tcp_udp_frames", "packets (switch-counted)"), ("ipv4_tcp_udp_frame_bytes", "Ethernet bytes"),
                   ("tcp_payload_bytes_out", "client payload bytes"), ("tcp_payload_bytes_in", "server payload bytes"),
                   ("tls_records", "TLS records (4 cleartext + 12 encrypted)"), ("rst_from_server", "RST from server"),
                   ("fin_frames", "FIN segments")):
        t_wire.append([lab] + [arrow(ds[(m, "curl_get_root_http")]["wire"][k], ds[(m, "curl_get_root_https")]["wire"][k])
                               for m in MODES])
    ps = D["paired_signals"]
    t_net, t_host = [], []
    for s in ps["amd64_static"]:
        is_host = s.startswith("host_")
        stat = "sum" if s in ("host_total_syscalls_total", "host_transition_count_total") else "max"
        row = [("`%s`" % s) + (" (sum)" if stat == "sum" else "")]
        for m in MODES:
            va, vb = ps[m][s]["http_" + stat], ps[m][s]["https_" + stat]  # first = dataset row (revision5)
            cell = arrow(round(va[0], 4), round(vb[0], 4))
            spans = ["%s repeats %s–%s" % (lab, num(round(min(x), 4)), num(round(max(x), 4)))
                     for lab, x in (("HTTP", va), ("HTTPS", vb)) if max(x) - min(x) > 1e-9 * max(1.0, abs(max(x)))]
            row.append(cell + ("; " + "; ".join(spans) if spans else ""))
        (t_host if is_host else t_net).append(row)
    t_sys = []
    for m in MODES:
        a, b = Counter(ds[(m, "curl_get_root_http")]["target_syscalls"]), Counter(ds[(m, "curl_get_root_https")]["target_syscalls"])
        diff = sorted(((k, b[k] - a[k]) for k in set(a) | set(b) if b[k] != a[k]), key=lambda kv: -abs(kv[1]))[:6]
        t_sys.append([m, "%d → %d" % (sum(a.values()), sum(b.values())), ", ".join("%s %+d" % kv for kv in diff)])
    order = ["transport", "options", "program", "request:post", "request:headers", "request:index", "url", "tls-option"]
    t_con = []
    for name in order:
        for m in MODES:
            c = con.get((name, m))
            if not c:
                continue
            n, h = c["network"], c["host"]
            t_con.append(["**%s**" % name if name == "transport" else name, m, "%d/%d" % (len(c["runs_a"]), len(c["runs_b"])),
                          "%d / %d" % (n["changed"], n["separated"]), "%.2f" % n["distance"]["between_means"],
                          num(n["distance"]["mean_within_pair"], 2), num(n["distance"]["perm_p"], 2),
                          "%d / %d" % (h["changed"], h["separated"]), "%.2f" % h["distance"]["between_means"],
                          num(h["distance"]["mean_within_pair"], 2)])
    for c in ports:
        n, h = c["network"], c["host"]
        t_con.append(["port (telnet %s)" % c["binary_a"][:8], c["mode"], "%d/%d" % (len(c["runs_a"]), len(c["runs_b"])),
                      "%d / %d" % (n["changed"], n["separated"]), "%.2f" % n["distance"]["between_means"],
                      num(n["distance"]["mean_within_pair"], 2), num(n["distance"]["perm_p"], 2),
                      "%d / %d" % (h["changed"], h["separated"]), "%.2f" % h["distance"]["between_means"],
                      num(h["distance"]["mean_within_pair"], 2)])
    t_det = []
    for m in MODES:
        c = con[("transport", m)]["detectors"]
        for d in DET:
            x = c[d]
            t_det.append([m, d, "%.2f → %.2f" % (x["flag_rate_a"], x["flag_rate_b"]),
                          "%.3f → %.3f" % (x["mean_prob_a"], x["mean_prob_b"]), frac(x["disagree_between"]),
                          frac(x["disagree_within_repeats"])])
    pooled = D["transport_pairs_pooled"]
    ref = {}
    for name in ("program", "options", "request:post", "request:headers", "request:index", "url", "tls-option"):
        ref[name] = {d: [sum(c["detectors"][d]["disagree_between"][0] for (n2, _), c in con.items() if n2 == name),
                         sum(c["detectors"][d]["disagree_between"][1] for (n2, _), c in con.items() if n2 == name)]
                     for d in DET}
    t_flips = [["**HTTP → HTTPS (transport)**"] + ["**%s**" % frac(pooled[d]["disagree_between"]) for d in DET],
               ["repeats of one task (all transport repeats)"] + [frac(pooled[d]["disagree_within_repeats"]) for d in DET]]
    for name, lab in (("program", "curl → wget (same GET /)"), ("options", "curl -s → progress meter on"),
                      ("request:headers", "GET / → GET /headers -D"), ("request:post", "GET / → POST /submit"),
                      ("url", "wget GET / → GET /data"), ("tls-option", "openssl SNI → -tls1_3 (TLS both)")):
        t_flips.append([lab] + [frac(ref[name][d]) for d in DET])
    cls = D["flag_rate_by_transport_class"]
    t_cls = []
    for k, lab in (("http", "cleartext HTTP tasks (curl, wget)"), ("https", "curl over HTTPS"),
                   ("tls", "openssl s_client (TLS)"), ("tcp", "telnet (TCP connect, no TLS)")):
        t_cls.append([lab, "%d (%d dataset rows)" % (cls[k]["runs"], cls[k]["dataset_rows"])] +
                     ["%.2f" % cls[k][d]["flag_rate"] for d in DET])
    base = D["table_v_oof_flag_rates"]
    t_cls.append(["*reference: all 105 dataset benign rows (Table V OOF)*", "105"] +
                 ["%.2f" % base[d]["benign_105_flag_rate"] for d in DET])

    # ---------------------------------------------------------------------------- part 2 tables
    pr = {x["run"]: x for x in S["per_run"]}
    imp = ["lab-http-beacon-a", "lab-http-beacon-b", "lab-https-beacon-a", "lab-https-beacon-b",
           "lab-mtls-beacon-a", "lab-mtls-beacon-b", "lab-mtls-session-a", "lab-mtls-session-b",
           "lab-wg-session-a", "lab-wg-session-b", "lab-wg-beacon-a", "lab-wg-beacon-b"]
    t_sl = []
    for n in imp:
        x = pr[n]
        w2, w5 = x["wire_20s"], x["wire_5min"]
        t_sl.append(["`%s`" % n, x["position"], w5["transport_observed"],
                     "%d / %d / %d" % (w2["tcp_connections"], w2["tls_server_hello"], sum(w2["http_requests_cleartext"].values())),
                     "%d / %d" % (w2["ipv4_tcp_udp_frames"], w2["ipv4_tcp_udp_frame_bytes"]),
                     "%d / %d / %d" % (w5["tcp_connections"], w5["tls_server_hello"], sum(w5["http_requests_cleartext"].values())),
                     "%d / %d" % (w5["ipv4_tcp_udp_frames"], w5["ipv4_tcp_udp_frame_bytes"]),
                     "%d / %d" % (x["host_calls_20s"], x["host_calls_5min"]),
                     "%d / %d" % (x["stray_wireguard_packets"]["first_20s"], x["stray_wireguard_packets"]["5min"]),
                     x["return_code"]])
    stray_runs = [[x["position"], "`%s`" % x["run"], x["kind"], x["stray_wireguard_packets"]["first_20s"],
                   x["stray_wireguard_packets"]["5min"]] for x in sorted(S["per_run"], key=lambda x: x["position"])
                  if x["stray_wireguard_packets"]["5min"]]
    sig = S["per_signal"][CLEAN]
    t_bsig = []
    for s, stat, lab in (("net_pkts_total_delta", "sum", "packets"), ("net_bytes_total_delta", "sum", "bytes"),
                         ("net_bytes_ab_delta", "sum", "bytes guest → server"), ("net_bytes_ba_delta", "sum", "bytes server → guest"),
                         ("net_syn_delta", "sum", "SYN (≈ 2 per connection)"), ("net_rst_delta", "sum", "RST"),
                         ("net_flow_count_seen", "sum", "flow-windows (flows × windows active)"),
                         ("net_flow_duration_max", "max", "longest flow, s"), ("net_max_len_max", "max", "largest frame, B"),
                         ("host_total_syscalls_total", "sum", "host system calls"), ("host_entropy_mean", "mean", "host entropy (per-window mean)")):
        row = ["%s (`%s`, %s)" % (lab, s, stat)]
        for lab2 in ("20s", "5min"):
            for gname in ("http-beacon", "https-beacon", "mtls-beacon"):
                v = sig[lab2][s][gname][stat]
                row.append(" / ".join(num(round(x, 3), 4) for x in v))
        t_bsig.append(row)
    t_scon = []
    for c in S["contrasts"]:
        if c["variant"] != CLEAN:
            continue
        n, h = c["testbed_sd"]["network"], c["testbed_sd"]["host"]
        t_scon.append([c["length"], c["role"], "%s vs %s" % (c["a"], c["b"]),
                       "%.1f" % n["distance"]["between_means"], "%.1f" % n["distance"]["mean_within_pair"],
                       "%d" % n["change_exceeds_both_repeat_differences"],
                       "%.1f" % h["distance"]["between_means"], "%.1f" % h["distance"]["mean_within_pair"],
                       "%d" % h["change_exceeds_both_repeat_differences"]])
    t_sdet = []
    for v in ("as_collected", CLEAN):
        pf = S["detectors"][v]["probabilities_first_20s"]
        for n in imp[:6]:
            t_sdet.append([v.replace("_", " "), "`%s`" % n] +
                          ["%.3f%s" % (pf[n][d], " ✓" if pf[n][d] >= .5 else "") for d in DET])
    t_sdec = []
    for v in ("as_collected", CLEAN):
        dec = S["detectors"][v]["decisions_first_20s"]
        t_sdec.append([v.replace("_", " ")] + ["%d/%d beacons; %d/%d benign" % (dec[d]["beacons_flagged"], dec[d]["beacons"],
                                                                                 dec[d]["benign_flagged"], dec[d]["benign"])
                                                for d in DET])
    t_blk = []
    for v in ("as_collected", CLEAN):
        bl = S["detectors"][v]["blocks_20s"]
        for gname in ("http-beacon", "https-beacon", "mtls-beacon", "benign"):
            t_blk.append([v.replace("_", " "), gname] + ["%.2f" % bl[gname][d]["flag_rate_all_blocks"] for d in DET])

    # ---------------------------------------------------------------------------- key numbers
    tr = [con[("transport", m)] for m in MODES]
    key = {
        "dataset": {
            "gate": D["gate"],
            "runs": D["n_runs"], "runs_by_source": D["runs_by_source"],
            "pairs": {m: {"http": ds[(m, "curl_get_root_http")]["execution_id"],
                          "https": ds[(m, "curl_get_root_https")]["execution_id"],
                          "binary_sha256": ds[(m, "curl_get_root_http")]["binary_sha256"],
                          "repeats_per_side": [len(c["runs_a"]), len(c["runs_b"])],
                          "transport_observed": [ds[(m, "curl_get_root_http")]["wire"]["transport_observed"],
                                                 ds[(m, "curl_get_root_https")]["wire"]["transport_observed"]]}
                      for m, c in zip(MODES, tr)},
            "transport_network_distance_dataset_sd": {m: c["network"]["distance"]["between_means"] for m, c in zip(MODES, tr)},
            "transport_host_distance_dataset_sd": {m: c["host"]["distance"]["between_means"] for m, c in zip(MODES, tr)},
            "transport_network_columns_changed_separated": {m: [c["network"]["changed"], c["network"]["separated"]] for m, c in zip(MODES, tr)},
            "max_network_distance_other_contrasts": max(c["network"]["distance"]["between_means"] for c in D["contrasts"]
                                                        if c["contrast"] != "transport"),
            "max_host_distance_other_contrasts": max(c["host"]["distance"]["between_means"] for c in D["contrasts"]
                                                     if c["contrast"] != "transport"),
            "decision_changes_http_https_pairs": {d: pooled[d]["disagree_between"] for d in DET},
            "decision_changes_between_repeats": {d: pooled[d]["disagree_within_repeats"] for d in DET},
            "decision_changes_curl_to_wget_pairs": ref["program"],
            "flag_rate_by_transport_class": {k: {d: cls[k][d]["flag_rate"] for d in DET} for k in cls},
        },
        "sliver": {
            "switch_model_recompute_equals_telemetry_max_rel_diff": S["switch_model_recompute_equals_telemetry_max_rel_diff"],
            "as_collected_scores_reproduce_saved_max_diff": S["as_collected_scores_reproduce_saved_sliver_results_max_diff_3dp"],
            "stray_wireguard_runs": [[r[1].strip("`"), r[3], r[4]] for r in stray_runs],
            "first_20s_decisions": {v: {d: {"beacons_flagged": S["detectors"][v]["decisions_first_20s"][d]["beacons_flagged"],
                                            "benign_flagged": S["detectors"][v]["decisions_first_20s"][d]["benign_flagged"],
                                            "between_transport_disagreements": S["detectors"][v]["decisions_first_20s"][d]["disagree_between_transport_pairs"],
                                            "within_transport_disagreements": S["detectors"][v]["decisions_first_20s"][d]["disagree_within_transport_pairs"]}
                                        for d in DET} for v in ("as_collected", CLEAN)},
            "block_flag_rates_clean": {g: {d: S["detectors"][CLEAN]["blocks_20s"][g][d]["flag_rate_all_blocks"] for d in DET}
                                       for g in ("http-beacon", "https-beacon", "mtls-beacon", "benign")},
            "contrasts_clean": [{k: c[k] for k in ("length", "role", "a", "b")} |
                                {"network_D": c["testbed_sd"]["network"]["distance"]["between_means"],
                                 "network_D_repeats": c["testbed_sd"]["network"]["distance"]["mean_within_pair"],
                                 "host_D": c["testbed_sd"]["host"]["distance"]["between_means"],
                                 "host_D_repeats": c["testbed_sd"]["host"]["distance"]["mean_within_pair"]}
                                for c in S["contrasts"] if c["variant"] == CLEAN],
        },
    }
    write_outputs(key, D, S, locals())


def rng(vals, fmt="%.1f"):
    lo, hi = min(vals), max(vals)
    return (fmt % lo) if fmt % lo == fmt % hi else "%s–%s" % (fmt % lo, fmt % hi)


README = Template(r"""# Encrypted-traffic check of the features (offline, 2026-11-15)

Committee request: *"an explicit encrypted-traffic evaluation ... showing the features don't shift"*. This folder
answers it with captures that already exist. The separate VM collection (one client over plaintext, TLS 1.1/1.2/1.3
and QUIC) is not part of it. Offline and read-only: no VM was operated, nothing from the collections was run, no
existing file was changed; benign client binaries were only hashed in memory, to prove that repeats use the same
file. `/usr/bin/python3`, scikit-learn 1.7.0 (needed to reproduce Table V).

Two paired comparisons:

1. **Dataset benign clients, HTTP vs HTTPS.** The release dataset holds the same static/dynamic `curl` binary twice
   per execution mode: task `a` fetches `http://10.0.0.1/` (`--fail -s`), task `b` fetches `https://10.0.0.1/`
   (`-sk`), same lab server (INetSim on the Sink). The same binaries with the same arguments were also run, with the
   same `.21` runner and settings from the same quiet guest image, in four earlier phases (the superseded revision5
   attempt's benign preflight, the v21 collection and its two benign preflights, 2026-10-24/25). Those runs serve
   only as repeats: $n_runs runs in all ($by_source), of curl, wget, openssl `s_client` and telnet. They also give
   the yardsticks: other harmless changes of a cleartext task (other request, other curl options, curl → wget, other
   URL), two TLS variants of `openssl s_client`, and telnet to port 80 vs 443 (TCP connect only).
2. **Sliver implants, HTTP vs HTTPS vs mutual TLS.** Our own implants under our own server in the sealed lab
   (`sliver-c2-5min/20261113T175035504465Z`): same framework and beacon configuration (5-s interval, no jitter), two
   separately generated implants per transport (`a`, `b` = repeats), 5-min runs, the same scripted operator taskings
   for every implant (one in the first 20 s, twelve in 5 min).

## Bottom line

* **The features do shift under encryption, deterministically.** Repeats of one task are nearly identical (HTTPS
  repeats differ by at most two teardown packets), so every change beyond them is systematic. What matters is how large the shift is next to other harmless changes, and
  whether a detector's decision changes.
* **Network, curl over HTTP vs HTTPS (3 builds).** TLS 1.3 adds the ClientHello ($ch B of TCP payload), the
  server's first flight with its certificate ($sf B), the client's Finished, two more encrypted 250-B server records
  right after the handshake (consistent with OpenSSL's two default session tickets), 22 B of framing and tag per
  record and two close_notify alerts; the lab server then ends the connection with RSTs. On the wire (dataset rows):
  $w_pk packets, $w_by Ethernet bytes, client payload $w_out B, server payload $w_in B. In the switch features the
  mean server-to-client packet grows from $w_avgba_http B to $w_avgba B, the down/up byte ratio from $w_ratio_http to
  $w_ratio, the flow lasts $w_dur ms instead of $w_dur_http ms; flow count, direction and SYNs are unchanged.
  $net_changed of 145 network columns move, $net_sep of them outside the range of the repeats. In units of each
  column's SD over the 240 dataset rows, the HTTP and HTTPS means are $net_D apart, against at most $other_net_D for
  every cleartext task change examined and at most $rep_D between repeats. Only three columns move by more than half a
  dataset SD in every build: the maximum and the SD of the server-to-client mean packet size ($z1 and $z2 SD) and the
  maximum down/up byte ratio ($z3 SD); all others by at most $z_rest SD.
* **Host, same runs.** The TLS library's own work: the static musl builds churn their allocator ($sys_st for
  amd64, $sys_i386 for i386; entropy $ent_st and $ent_i386), the glibc build reads and calls `getpid` more
  ($sys_dyn). The host shift ($host_D) is about as large as switching curl to wget ($prog_host_D) or turning on curl's
  progress meter ($opt_host_D).
* **Decisions (Table V fold models, 10 assignments; both runs of a pair are scored by the same model).** The
  network detector never changes its decision ($f_net HTTP/HTTPS pairs) and never flags these clients (mean
  probability $p_net). The host detector changes in $f_host pairs ($f_host_dir of them toward fewer alarms on HTTPS),
  the concatenated hybrid in $f_concat ($f_concat_dir), the stacked hybrid in $f_stacked ($f_stacked_dir). Switching
  curl to wget changes them in $p_host, $p_concat and $p_stacked pairs. Between repeats of one task: $f_rep for every
  detector.
* **Sliver beacons.** Every check-in opens a new connection ($sl_conn in 5 min for all three transports). HTTPS and
  mTLS add a TLS 1.3 handshake to each: Go's ClientHello carries a post-quantum X25519MLKEM768 key share ($sl_ch B,
  against $ch B for curl's OpenSSL 3.0), so bytes rise $sl_bytes_x (HTTP $sl_b_http kB, HTTPS $sl_b_https kB, mTLS
  $sl_b_mtls kB in 5 min), server-to-guest bytes $sl_ba_x, and connections end with RSTs ($sl_rst in 5 min vs none
  for HTTP); mTLS connections stay open about 1 s (packets in 5 min: HTTP $sl_p_http, HTTPS $sl_p_https, mTLS
  $sl_p_mtls). On the network side the transports are $sl_ratio5 times farther apart than the two implants of one
  transport after 5 min, but only $sl_ratio20 times after 20 s (HTTP vs HTTPS: $sl_hh20 vs $sl_hh20r). Host features
  of HTTP and HTTPS beacons are within the a/b spread; mTLS is modestly apart. Changing the C2 mode (mTLS beacon →
  mTLS session) moves the features more than any transport change ($sl_mode_net network, $sl_mode_host host at 5 min).
  **No decision depends on the transport:** host, concatenated and stacked hybrids flag all six beacons at 20 s, and in
  the thirty 20-s blocks per transport over 5 min host and concatenated flag 100% for every transport, stacked
  $sl_blk_st; the network detector flags none of the beacons (0% of blocks).
* **Artifact found in the Sliver attempt, and corrected.** The server's WireGuard listener kept sending handshake
  initiations (UDP from 10.0.0.1:51820, about one per 5 s, answered by ICMP port unreachable) into four later runs
  (collection positions $stray_pos). The switch counts them as one long UDP flow. They caused the network detector's
  only beacon alarm (`lab-https-beacon-b`) and three benign false alarms of the earlier testbed analysis
  (`analysis/sliver_results.json`). With those packets removed (release `features/switch_model.py`, unchanged, on the
  same captures; unfiltered it reproduces the collected telemetry exactly) benign alarms at 20 s fall from $ben_before
  to $ben_after of 12 (host / network / concatenated / stacked); implants are unchanged for host, concatenated and
  stacked (10 of 12), network $imp_net_before → $imp_net_after of 12.

**Verdict.** *"The features don't shift"* cannot be claimed: encryption changes the payload-free features, mostly
sizes, byte ratios and connection teardown, deterministically and more than any other harmless change of a task in
these data. What the data support: (1) for the curl pairs the number of flows and connections, their direction and the
SYN counts are unchanged, and the Sliver beacons open the same number of connections in all three transports; (2) the
network detector's decision did not change on any HTTP/HTTPS pair, nor between Sliver transports once the stray
WireGuard packets are removed;
(3) host and stacked-hybrid decisions changed on the curl pairs about as often as when curl is replaced by wget
($f_host vs $p_host and $f_stacked vs $p_stacked pairs), nearly always toward fewer false alarms on HTTPS; the
concatenated hybrid changed more often ($f_concat vs $p_concat), in both directions; (4) for the Sliver implants no detector's
decision depended on the transport. The samples are small and specific (one tiny curl request in three builds; two
implants per Sliver transport); the VM collection is the systematic test.

## 1. Dataset benign clients: HTTP vs HTTPS

### Pairs (curl `GET /`, same binary, same server)

$T_pairs

Transport as seen by tshark in the feature windows (record layer, any port). The HTTP and HTTPS rows of one mode share
the cross-validation group `benign_project::curl`, so in every fold assignment both are scored by the same model.

### On the wire (dataset rows; HTTPS repeats differ from them by at most two teardown packets, RST/ACK)

$T_wire

### Switch features: value in the active window, HTTP dataset row → HTTPS dataset row (range over repeats where they differ)

These one-shot clients send everything in window 0; the flow stays in the active set for three more windows.

$T_net

### Host features (same rows)

$T_host

Where the host change comes from (raw system calls of the `curl` process, dataset rows):

$T_sys

### Shift against repeats and against other harmless changes

Per contrast: columns that change at all / columns whose two sets of repeats do not overlap; `D` = Euclidean distance
between the two means with every column divided by its SD over the 240 dataset rows (145 network or 90 host columns);
`D repeats` = mean distance between two repeats of one task; `perm p` = exact permutation p-value of the network `D`
over all relabelings of the runs (only with at least 3 runs per side; 0.0079 is the smallest possible with 5 + 5).

$T_con

The telnet rows are a control: port 80 vs 443 is a bare TCP connect either way (no TLS from the client); the lab's TLS
service answers with a 7-byte alert, the HTTP service does not, which alone moves 65 columns by 0.64.

### Detector decisions (Table V protocol: out-of-fold for the dataset rows, the same fold models for the repeats)

$T_det

Pooled over the three builds, against pairs of runs that differ in something else (all pairs scored by the same fold
model; every count is pairs × fold assignments, and repeats are near-identical, so the effective sample is three builds
× ten assignments):

$T_flips

Flag rate by transport over all runs (fraction of runs × assignments). The TLS runs are flagged no more often than
the cleartext ones by any detector; the only class the network detector flags is the bare TCP connect (telnet):

$T_cls

## 2. Sliver implants: HTTP vs HTTPS vs mutual TLS

### Runs (as captured; `pos` = position in the collection order)

$T_sl

The HTTP transport carries Sliver's own encrypted, encoded messages in cleartext HTTP requests (one POST body even
starts like a PNG file) and begins with one TLS ClientHello ($sl_ch B) that the HTTP listener rejects (HTTP 400)
before falling back to HTTP. In the HTTPS and mTLS beacons the RSTs come from the Go client, not the server. The WireGuard beacons exited
(status 2) without traffic and are not compared.

### Stray WireGuard packets

$T_stray

### Totals per implant (`a / b`; switch features without the stray packets)

$T_bsig

Frames larger than 1,514 B are TCP segmentation/receive-offload frames seen by the guest-side capture; a switch would
see them split. They occur in every transport.

### Shift against the a/b spread (without the stray packets; scale = column SD over the testbed's 27 runs)

$T_scon

### Detector decisions (trained on all 240 dataset rows, applied to the first 40 windows)

$T_sdet

$T_sdec

Every consecutive 20-s block of the 5-min runs (15 per implant, 30 per transport; blocks after the first lack the
process start, so host and hybrid scores there are outside the training conditions):

$T_blk

## 3. Caveats

1. The paired dataset evidence is one program (curl, three builds) making one tiny request. One-shot requests carry the
   largest relative TLS overhead; long sessions dilute it. The cross-program groups (wget, openssl, telnet) differ in
   more than the transport.
2. Only TLS 1.3 occurs (every ServerHello negotiates 0x0304). The handshake size depends on the stack and options:
   ClientHello $ch B for curl, 316 B for `s_client` with SNI, 225 B for `s_client -tls1_3` (OpenSSL 3.0, X25519), $sl_ch B
   for Sliver (Go, X25519MLKEM768). TLS 1.2, QUIC and session resumption are not covered here.
3. The lab server is INetSim with its own certificate (`curl -k`); its TLS service closes with RSTs, so part of the RST
   change is server behaviour. In the Sliver runs the RSTs come from the Go client.
4. Repeats are near-deterministic, so "beyond run-to-run spread" is a weak bar; that is why other harmless task
   changes are the yardstick.
5. Decision counts are pairs × fold assignments; the repeats are near-identical, so the counts are not independent.
6. Sliver: two implants per transport; the C2 server is ours and answers; runner `.22` (= `.21` plus an event-count
   guard, same features); the detectors were trained on the 240 dataset rows (20 s), so blocks after the first 20 s
   are outside the training conditions; the stray WireGuard packets are an artifact of the testbed, removed here only
   for runs that are not WireGuard implants.
7. Post hoc and descriptive: nothing here was pre-registered, and no model was tuned on these runs.
8. Side effect: the first run of `sliver_transports.py` (without `-B`) refreshed the stale bytecode cache
   `sliver-c2-5min/__pycache__/analyze_sliver.cpython-310.pyc` of the unchanged frozen source; nothing else outside this
   folder was written. Use `-B` to avoid it.

## 4. Files and reproduction

```sh
cd committee-eval-20261113/encryption
nice -n 19 /usr/bin/python3 -B dataset_http_https.py --jobs 4   # part 1 -> results_dataset.json, columns_dataset.csv
nice -n 19 /usr/bin/python3 -B sliver_transports.py             # part 2 -> results_sliver.json
/usr/bin/python3 -B report.py                                   # results.json, tables.md, README.md, SHA256SUMS
```

Gates (all asserted by the scripts): the cached Table V out-of-fold probabilities reproduce host $g_host / network
$g_net / stacked $g_stacked (mean of ten fold assignments); the 26 refit fold models reproduce those cached
probabilities for the dataset rows exactly (max difference $g_refit); every dataset row rebuilt from its run equals
`features.csv`; tshark's in-window IPv4 TCP/UDP packet and byte counts equal the switch features of every run; the
release switch model reproduces the Sliver runs' collected switch features exactly; the as-collected Sliver scores
reproduce the saved `analysis/sliver_results.json`.

$T_files
""")


def write_outputs(key, D, S, L):
    pooled = D["transport_pairs_pooled"]
    con = {(c["contrast"], c["mode"]): c for c in D["contrasts"] if c["contrast"] != "port"}
    tr = {m: con[("transport", m)] for m in MODES}
    ref, ds = L["ref"], L["ds"]
    key["dataset"]["decision_change_directions_http_https"] = {
        d: {"only_http_flagged": pooled[d]["only_http_flagged"], "only_https_flagged": pooled[d]["only_https_flagged"]}
        for d in DET}
    files = ["wire.py", "contrast.py", "dataset_http_https.py", "sliver_transports.py", "report.py",
             "results_dataset.json", "results_sliver.json", "columns_dataset.csv",
             "dataset_http_https.log", "sliver_transports.log"]
    key["files_sha256"] = {f: sha(HERE / f) for f in files}
    key["inputs_sha256"] = {
        "features.csv": sha("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv"),
        "cache/cv_published_k40.npz": D["gate"]["cache_sha256"],
        "switch_model.py": S["switch_model_sha256"], "sliver protocol.json": S["protocol_sha256"]}
    (HERE / "results.json").write_text(json.dumps(key, indent=1))

    T = {"pairs": table(["mode", "HTTP row", "HTTPS row", "curl SHA-256 (16)", "runs (HTTP + HTTPS)", "tshark"], L["t_pairs"]),
         "wire": table(["", *MODES], L["t_wire"]),
         "net": table(["switch signal", *MODES], L["t_net"]),
         "host": table(["host signal (max over windows; sum where marked)", *MODES], L["t_host"]),
         "sys": table(["mode", "curl system calls", "largest changes (HTTPS − HTTP)"], L["t_sys"]),
         "con": table(["contrast", "mode", "runs", "net changed / separated", "net D", "net D repeats", "net perm p",
                       "host changed / separated", "host D", "host D repeats"], L["t_con"]),
         "det": table(["mode", "detector", "flag rate HTTP → HTTPS", "mean p HTTP → HTTPS",
                       "decision changes, HTTP vs HTTPS pairs", "decision changes, repeat pairs"], L["t_det"]),
         "flips": table(["pairs of runs", *DET], L["t_flips"]),
         "cls": table(["runs", "n", *DET], L["t_cls"]),
         "sl": table(["implant", "pos", "transport (tshark, 5 min)", "20 s: TCP conn / TLS handshakes / HTTP requests",
                      "20 s: packets / bytes", "5 min: TCP conn / TLS / HTTP", "5 min: packets / bytes",
                      "host calls 20 s / 5 min", "stray WG pkts 20 s / 5 min", "rc"], L["t_sl"]),
         "stray": table(["pos", "run", "kind", "stray WG packets, first 20 s", "5 min"], L["stray_runs"]),
         "bsig": table(["signal", "20 s HTTP", "20 s HTTPS", "20 s mTLS", "5 min HTTP", "5 min HTTPS", "5 min mTLS"], L["t_bsig"]),
         "scon": table(["length", "role", "contrast", "net D", "net D a/b", "net cols > both a/b diffs",
                        "host D", "host D a/b", "host cols > both a/b diffs"], L["t_scon"]),
         "sdet": table(["variant", "implant", *DET], L["t_sdet"]),
         "sdec": table(["variant", *DET], L["t_sdec"]),
         "blk": table(["variant", "runs", *DET], L["t_blk"])}
    (HERE / "tables.md").write_text("\n\n".join("<!-- %s -->\n%s" % kv for kv in T.items()) + "\n")
    hashes = {f: sha(HERE / f) for f in files + ["results.json", "tables.md"]}
    T["files"] = table(["file", "SHA-256"], [["`%s`" % f, "`%s`" % h] for f, h in hashes.items()] +
                       [["input `%s`" % k, "`%s`" % v] for k, v in key["inputs_sha256"].items()])

    w = {m: (ds[(m, "curl_get_root_http")]["wire"], ds[(m, "curl_get_root_https")]["wire"]) for m in MODES}

    def sysd(m, calls):
        a, b = ds[(m, "curl_get_root_http")]["target_syscalls"], ds[(m, "curl_get_root_https")]["target_syscalls"]
        return ", ".join("%+d `%s`" % (b.get(c, 0) - a.get(c, 0), c) for c in calls)
    ps = D["paired_signals"]
    zl = {m: tr[m]["network"]["largest_z"] for m in MODES}
    sig = S["per_signal"][CLEAN]["5min"]
    sc = {(c["length"], c["a"], c["b"]): c for c in S["contrasts"] if c["variant"] == CLEAN}
    dist = lambda c, b: c["testbed_sd"][b]["distance"]  # noqa: E731
    tpairs = [("http-beacon", "https-beacon"), ("http-beacon", "mtls-beacon"), ("https-beacon", "mtls-beacon")]
    dec = {v: S["detectors"][v]["decisions_first_20s"] for v in ("as_collected", CLEAN)}
    flagged = lambda v, d: sum(sum(x) for g, x in dec[v][d]["flagged"].items() if g not in ("benign", "null"))  # noqa: E731
    blk = S["detectors"][CLEAN]["blocks_20s"]
    pr = {x["run"]: x for x in S["per_run"]}
    beacons = {t: [pr["lab-%s-beacon-%s" % (t, s)] for s in "ab"] for t in ("http", "https", "mtls")}
    v = dict(
        n_runs=D["n_runs"],
        by_source="%d dataset rows from revision5, repeats %s" % (D["runs_by_source"]["rev5"], ", ".join(
            "%d %s" % (n, s) for s, n in D["runs_by_source"].items() if s != "rev5")),
        ch=w["amd64_dynamic"][1]["tls_client_hello_segment_bytes"][0],
        sf=w["amd64_dynamic"][1]["tls_server_hello_segment_bytes"][0],
        w_pk=rng([w[m][0]["ipv4_tcp_udp_frames"] for m in MODES], "%d") + " → " + rng([w[m][1]["ipv4_tcp_udp_frames"] for m in MODES], "%d"),
        w_by="%s → %s" % (rng([w[m][0]["ipv4_tcp_udp_frame_bytes"] for m in MODES], "%d"),
                         rng([w[m][1]["ipv4_tcp_udp_frame_bytes"] for m in MODES], "%d")),
        w_out="%d → %d" % (w["amd64_dynamic"][0]["tcp_payload_bytes_out"], w["amd64_dynamic"][1]["tcp_payload_bytes_out"]),
        w_in="%d → %d" % (w["amd64_dynamic"][0]["tcp_payload_bytes_in"], w["amd64_dynamic"][1]["tcp_payload_bytes_in"]),
        w_avgba=rng([ps[m]["net_avg_pkt_size_ba_delta"]["https_max"][0] for m in MODES], "%.0f"),
        w_avgba_http=rng([ps[m]["net_avg_pkt_size_ba_delta"]["http_max"][0] for m in MODES], "%.0f"),
        w_ratio_http=rng([ps[m]["net_down_up_ratio_delta"]["http_max"][0] for m in MODES], "%.2f"),
        w_dur_http=rng([1000 * ps[m]["net_flow_duration_max"]["http_max"][0] for m in MODES], "%.0f"),
        net_changed=rng([tr[m]["network"]["changed"] for m in MODES], "%d"),
        net_sep=rng([tr[m]["network"]["separated"] for m in MODES], "%d"),
        ent_st="%.1f → %.1f" % (ps["amd64_static"]["host_entropy_max"]["http_max"][0],
                                ps["amd64_static"]["host_entropy_max"]["https_max"][0]),
        ent_i386="%.1f → %.1f" % (ps["i386_static"]["host_entropy_max"]["http_max"][0],
                                  ps["i386_static"]["host_entropy_max"]["https_max"][0]),
        sys_st=sysd("amd64_static", ("mmap", "munmap")), sys_i386=sysd("i386_static", ("mmap2", "munmap")),
        sys_dyn=sysd("amd64_dynamic", ("read", "getpid")),
        w_ratio=rng([ps[m]["net_down_up_ratio_delta"]["https_max"][0] for m in MODES], "%.2f"),
        w_dur=rng([1000 * ps[m]["net_flow_duration_max"]["https_max"][0] for m in MODES], "%.0f"),
        net_D=rng([tr[m]["network"]["distance"]["between_means"] for m in MODES]),
        other_net_D="%.2f" % key["dataset"]["max_network_distance_other_contrasts"],
        rep_D="%.2f" % max(tr[m]["network"]["distance"]["mean_within_pair"] for m in MODES),
        z1=rng([zl[m][0][1] for m in MODES], "%+.1f"), z2=rng([zl[m][1][1] for m in MODES], "%+.1f"),
        z3=rng([zl[m][2][1] for m in MODES], "%+.1f"), z_rest="%.2f" % max(abs(zl[m][3][1]) for m in MODES),
        host_D=rng([tr[m]["host"]["distance"]["between_means"] for m in MODES]),
        prog_host_D=rng([con[("program", m)]["host"]["distance"]["between_means"] for m in MODES]),
        opt_host_D="%.1f" % con[("options", "amd64_dynamic")]["host"]["distance"]["between_means"],
        f_net=frac(pooled["network"]["disagree_between"]), f_host=frac(pooled["host"]["disagree_between"]),
        f_concat=frac(pooled["concat"]["disagree_between"]), f_stacked=frac(pooled["stacked"]["disagree_between"]),
        f_host_dir="%d" % pooled["host"]["only_http_flagged"],
        f_concat_dir="%d with only HTTP flagged, %d with only HTTPS flagged" % (
            pooled["concat"]["only_http_flagged"], pooled["concat"]["only_https_flagged"]),
        f_stacked_dir="%d with only HTTP flagged" % pooled["stacked"]["only_http_flagged"],
        p_net="%s → %s" % (rng([tr[m]["detectors"]["network"]["mean_prob_a"] for m in MODES], "%.2f"),
                           rng([tr[m]["detectors"]["network"]["mean_prob_b"] for m in MODES], "%.2f")),
        p_host=frac(ref["program"]["host"]), p_concat=frac(ref["program"]["concat"]), p_stacked=frac(ref["program"]["stacked"]),
        f_rep="0 of %d pairs" % pooled["host"]["disagree_within_repeats"][1],
        sl_conn=rng([x["wire_5min"]["tcp_connections"] for t in beacons for x in beacons[t]], "%d"),
        sl_ch=beacons["https"][0]["wire_5min"]["tls_client_hello_segment_bytes"][0],
        sl_b_http=rng([b / 1000 for b in sig["net_bytes_total_delta"]["http-beacon"]["sum"]], "%.0f"),
        sl_b_https=rng([b / 1000 for b in sig["net_bytes_total_delta"]["https-beacon"]["sum"]], "%.0f"),
        sl_b_mtls=rng([b / 1000 for b in sig["net_bytes_total_delta"]["mtls-beacon"]["sum"]], "%.0f"),
        sl_bytes_x=rng([t / h for g in ("https-beacon", "mtls-beacon") for t in sig["net_bytes_total_delta"][g]["sum"]
                        for h in sig["net_bytes_total_delta"]["http-beacon"]["sum"]], "%.1f") + "×",
        sl_ba_x=rng([t / h for g in ("https-beacon", "mtls-beacon") for t in sig["net_bytes_ba_delta"][g]["sum"]
                     for h in sig["net_bytes_ba_delta"]["http-beacon"]["sum"]], "%.1f") + "×",
        sl_rst=rng([x for g in ("https-beacon", "mtls-beacon") for x in sig["net_rst_delta"][g]["sum"]], "%d"),
        sl_p_http=rng(sig["net_pkts_total_delta"]["http-beacon"]["sum"], "%d"),
        sl_p_https=rng(sig["net_pkts_total_delta"]["https-beacon"]["sum"], "%d"),
        sl_p_mtls=rng(sig["net_pkts_total_delta"]["mtls-beacon"]["sum"], "%d"),
        sl_ratio5=rng([dist(sc[("5min", a, b)], "network")["between_means"] /
                       dist(sc[("5min", a, b)], "network")["mean_within_pair"] for a, b in tpairs], "%.0f"),
        sl_ratio20=rng([dist(sc[("20s", a, b)], "network")["between_means"] /
                        dist(sc[("20s", a, b)], "network")["mean_within_pair"] for a, b in tpairs], "%.1f"),
        sl_hh20="%.1f" % dist(sc[("20s", "http-beacon", "https-beacon")], "network")["between_means"],
        sl_hh20r="%.1f" % dist(sc[("20s", "http-beacon", "https-beacon")], "network")["mean_within_pair"],
        sl_mode_net="%.1f" % dist(sc[("5min", "mtls-beacon", "mtls-session")], "network")["between_means"],
        sl_mode_host="%.1f" % dist(sc[("5min", "mtls-beacon", "mtls-session")], "host")["between_means"],
        sl_blk_st=" / ".join("%.0f%%" % (100 * blk[g]["stacked"]["flag_rate_all_blocks"])
                             for g in ("http-beacon", "https-beacon", "mtls-beacon")) + " (HTTP / HTTPS / mTLS)",
        stray_pos=", ".join(str(r[0]) for r in L["stray_runs"]),
        ben_before=" / ".join(str(dec["as_collected"][d]["benign_flagged"]) for d in DET),
        ben_after=" / ".join(str(dec[CLEAN][d]["benign_flagged"]) for d in DET),
        imp_net_before=flagged("as_collected", "network"), imp_net_after=flagged(CLEAN, "network"),
        g_host="%.3f" % D["gate"]["table_v_host"]["mean"], g_net="%.3f" % D["gate"]["table_v_network"]["mean"],
        g_stacked="%.3f" % D["gate"]["table_v_stacked"]["mean"],
        g_refit="%g" % D["gate"]["refit_reproduces_cached_oof_max_abs_diff"],
        **{"T_" + k: t for k, t in T.items()})
    assert all(flagged(var, d) == 10 for var in ("as_collected", CLEAN) for d in ("host", "concat", "stacked"))
    (HERE / "README.md").write_text(README.substitute(v))
    names = sorted(p.name for p in HERE.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (HERE / "SHA256SUMS").write_text("".join("%s  %s\n" % (sha(HERE / n), n) for n in names))
    print("wrote results.json, tables.md, README.md, SHA256SUMS")


if __name__ == "__main__":
    main()
