# Encrypted-traffic check of the features (offline, 2026-11-15)

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
   only as repeats: 114 runs in all (21 dataset rows from revision5, repeats 21 rev5-pre, 24 v21, 24 v21-pre2, 24 v21-pre1), of curl, wget, openssl `s_client` and telnet. They also give
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
* **Network, curl over HTTP vs HTTPS (3 builds).** TLS 1.3 adds the ClientHello (517 B of TCP payload), the
  server's first flight with its certificate (1421 B), the client's Finished, two more encrypted 250-B server records
  right after the handshake (consistent with OpenSSL's two default session tickets), 22 B of framing and tag per
  record and two close_notify alerts; the lab server then ends the connection with RSTs. On the wire (dataset rows):
  12 → 16–18 packets, 1288 → 4183–4309 Ethernet bytes, client payload 72 → 715 B, server payload 408 → 2408 B. In the switch features the
  mean server-to-client packet grows from 149 B to 366–409 B, the down/up byte ratio from 1.38 to
  2.12–2.18, the flow lasts 34–38 ms instead of 10–12 ms; flow count, direction and SYNs are unchanged.
  97 of 145 network columns move, 97 of them outside the range of the repeats. In units of each
  column's SD over the 240 dataset rows, the HTTP and HTTPS means are 3.7–4.2 apart, against at most 0.64 for
  every cleartext task change examined and at most 0.25 between repeats. Only three columns move by more than half a
  dataset SD in every build: the maximum and the SD of the server-to-client mean packet size (+2.8–+3.3 and +1.9–+2.3 SD) and the
  maximum down/up byte ratio (+1.0–+1.1 SD); all others by at most 0.51 SD.
* **Host, same runs.** The TLS library's own work: the static musl builds churn their allocator (+148 `mmap`, +148 `munmap` for
  amd64, +239 `mmap2`, +238 `munmap` for i386; entropy 4.0 → 3.4 and 4.5 → 3.4), the glibc build reads and calls `getpid` more
  (+24 `read`, +14 `getpid`). The host shift (0.5–1.7) is about as large as switching curl to wget (1.5–1.9) or turning on curl's
  progress meter (1.7).
* **Decisions (Table V fold models, 10 assignments; both runs of a pair are scored by the same model).** The
  network detector never changes its decision (0/540 HTTP/HTTPS pairs) and never flags these clients (mean
  probability 0.08 → 0.02). The host detector changes in 183/540 pairs (179 of them toward fewer alarms on HTTPS),
  the concatenated hybrid in 54/540 (29 with only HTTP flagged, 25 with only HTTPS flagged), the stacked hybrid in 29/540 (29 with only HTTP flagged). Switching
  curl to wget changes them in 195/540, 29/540 and 33/540 pairs. Between repeats of one task: 0 of 420 pairs for every
  detector.
* **Sliver beacons.** Every check-in opens a new connection (61–63 in 5 min for all three transports). HTTPS and
  mTLS add a TLS 1.3 handshake to each: Go's ClientHello carries a post-quantum X25519MLKEM768 key share (1495 B,
  against 517 B for curl's OpenSSL 3.0), so bytes rise 2.3–2.7× (HTTP 170–190 kB, HTTPS 447–455 kB, mTLS
  443–447 kB in 5 min), server-to-guest bytes 2.9–3.5×, and connections end with RSTs (123–129 in 5 min vs none
  for HTTP); mTLS connections stay open about 1 s (packets in 5 min: HTTP 733–737, HTTPS 1183–1208, mTLS
  1981–1990). On the network side the transports are 4–10 times farther apart than the two implants of one
  transport after 5 min, but only 1.4–2.6 times after 20 s (HTTP vs HTTPS: 10.9 vs 7.9). Host features
  of HTTP and HTTPS beacons are within the a/b spread; mTLS is modestly apart. Changing the C2 mode (mTLS beacon →
  mTLS session) moves the features more than any transport change (20.7 network, 14.6 host at 5 min).
  **No decision depends on the transport:** host, concatenated and stacked hybrids flag all six beacons at 20 s, and in
  the thirty 20-s blocks per transport over 5 min host and concatenated flag 100% for every transport, stacked
  93% / 90% / 100% (HTTP / HTTPS / mTLS); the network detector flags none of the beacons (0% of blocks).
* **Artifact found in the Sliver attempt, and corrected.** The server's WireGuard listener kept sending handshake
  initiations (UDP from 10.0.0.1:51820, about one per 5 s, answered by ICMP port unreachable) into four later runs
  (collection positions 17, 18, 19, 27). The switch counts them as one long UDP flow. They caused the network detector's
  only beacon alarm (`lab-https-beacon-b`) and three benign false alarms of the earlier testbed analysis
  (`analysis/sliver_results.json`). With those packets removed (release `features/switch_model.py`, unchanged, on the
  same captures; unfiltered it reproduces the collected telemetry exactly) benign alarms at 20 s fall from 6 / 5 / 5 / 6
  to 6 / 2 / 2 / 4 of 12 (host / network / concatenated / stacked); implants are unchanged for host, concatenated and
  stacked (10 of 12), network 3 → 2 of 12.

**Verdict.** *"The features don't shift"* cannot be claimed: encryption changes the payload-free features, mostly
sizes, byte ratios and connection teardown, deterministically and more than any other harmless change of a task in
these data. What the data support: (1) for the curl pairs the number of flows and connections, their direction and the
SYN counts are unchanged, and the Sliver beacons open the same number of connections in all three transports; (2) the
network detector's decision did not change on any HTTP/HTTPS pair, nor between Sliver transports once the stray
WireGuard packets are removed;
(3) host and stacked-hybrid decisions changed on the curl pairs about as often as when curl is replaced by wget
(183/540 vs 195/540 and 29/540 vs 33/540 pairs), nearly always toward fewer false alarms on HTTPS; the
concatenated hybrid changed more often (54/540 vs 29/540), in both directions; (4) for the Sliver implants no detector's
decision depended on the transport. The samples are small and specific (one tiny curl request in three builds; two
implants per Sliver transport); the VM collection is the systematic test.

## 1. Dataset benign clients: HTTP vs HTTPS

### Pairs (curl `GET /`, same binary, same server)

| mode | HTTP row | HTTPS row | curl SHA-256 (16) | runs (HTTP + HTTPS) | tshark |
|---|---|---|---|---|---|
| amd64_dynamic | `curl-net-amd64_dynamic` (row 87) | `curl-net-amd64_dynamic-2` (row 88) | `7dc07fd77b104e65` | 2 + 2 | HTTP cleartext / TLS1.3 |
| amd64_static | `curl-net-amd64_static` (row 126) | `curl-net-amd64_static-2` (row 127) | `d912f1862f9f39ca` | 5 + 5 | HTTP cleartext / TLS1.3 |
| i386_static | `curl-net-i386_static` (row 182) | `curl-net-i386_static-2` (row 183) | `ab7a2b716bea34fa` | 5 + 5 | HTTP cleartext / TLS1.3 |

Transport as seen by tshark in the feature windows (record layer, any port). The HTTP and HTTPS rows of one mode share
the cross-validation group `benign_project::curl`, so in every fold assignment both are scored by the same model.

### On the wire (dataset rows; HTTPS repeats differ from them by at most two teardown packets, RST/ACK)

|  | amd64_dynamic | amd64_static | i386_static |
|---|---|---|---|
| packets (switch-counted) | 12 → 16 (+33%) | 12 → 16 (+33%) | 12 → 18 (+50%) |
| Ethernet bytes | 1288 → 4183 (+225%) | 1288 → 4183 (+225%) | 1288 → 4309 (+235%) |
| client payload bytes | 72 → 715 (+893%) | 72 → 715 (+893%) | 72 → 715 (+893%) |
| server payload bytes | 408 → 2408 (+490%) | 408 → 2408 (+490%) | 408 → 2408 (+490%) |
| TLS records (4 cleartext + 12 encrypted) | 0 → 16 | 0 → 16 | 0 → 16 |
| RST from server | 0 → 2 | 0 → 2 | 0 → 3 |
| FIN segments | 2 (same) | 2 (same) | 2 → 3 (+50%) |

### Switch features: value in the active window, HTTP dataset row → HTTPS dataset row (range over repeats where they differ)

These one-shot clients send everything in window 0; the flow stays in the active set for three more windows.

| switch signal | amd64_dynamic | amd64_static | i386_static |
|---|---|---|---|
| `net_flow_count_seen` | 1 (same) | 1 (same) | 1 (same) |
| `net_pkts_total_delta` | 12 → 16 (+33%) | 12 → 16 (+33%); HTTPS repeats 14–16 | 12 → 18 (+50%); HTTPS repeats 16–18 |
| `net_bytes_total_delta` | 1288 → 4183 (+225%) | 1288 → 4183 (+225%); HTTPS repeats 4057–4183 | 1288 → 4309 (+235%); HTTPS repeats 4183–4309 |
| `net_pkts_ab_delta` | 7 → 9 (+29%) | 7 → 9 (+29%); HTTPS repeats 8–9 | 7 → 10 (+43%); HTTPS repeats 9–10 |
| `net_bytes_ab_delta` | 542 → 1317 (+143%) | 542 → 1317 (+143%); HTTPS repeats 1251–1317 | 542 → 1383 (+155%); HTTPS repeats 1317–1383 |
| `net_pkts_ba_delta` | 5 → 7 (+40%) | 5 → 7 (+40%); HTTPS repeats 6–7 | 5 → 8 (+60%); HTTPS repeats 7–8 |
| `net_bytes_ba_delta` | 746 → 2866 (+284%) | 746 → 2866 (+284%); HTTPS repeats 2806–2866 | 746 → 2926 (+292%); HTTPS repeats 2866–2932 |
| `net_min_len_mean` | 66 → 60 (-9%) | 66 → 60 (-9%) | 66 → 60 (-9%) |
| `net_max_len_mean` | 324 → 1487 (+359%) | 324 → 1487 (+359%) | 324 → 1487 (+359%) |
| `net_min_len_min` | 66 → 60 (-9%) | 66 → 60 (-9%) | 66 → 60 (-9%) |
| `net_max_len_max` | 324 → 1487 (+359%) | 324 → 1487 (+359%) | 324 → 1487 (+359%) |
| `net_avg_pkt_size_delta` | 107 → 261 (+144%) | 107 → 261 (+144%); HTTPS repeats 261–290 | 107 → 239 (+123%); HTTPS repeats 239–261 |
| `net_avg_pkt_size_ab_delta` | 77.4 → 146 (+89%) | 77.4 → 146 (+89%); HTTPS repeats 146–156 | 77.4 → 138 (+79%); HTTPS repeats 138–146 |
| `net_avg_pkt_size_ba_delta` | 149 → 409 (+174%) | 149 → 409 (+174%); HTTPS repeats 409–468 | 149 → 366 (+145%); HTTPS repeats 366–409 |
| `net_flow_duration_mean` | 0.0122 → 0.0341 (+180%); HTTP repeats 0.0112–0.0122; HTTPS repeats 0.0341–0.0366 | 0.0103 → 0.0378 (+267%); HTTP repeats 0.0103–0.0113; HTTPS repeats 0.0339–0.0381 | 0.0114 → 0.0356 (+212%); HTTP repeats 0.0099–0.0115; HTTPS repeats 0.034–0.0382 |
| `net_flow_duration_max` | 0.0122 → 0.0341 (+180%); HTTP repeats 0.0112–0.0122; HTTPS repeats 0.0341–0.0366 | 0.0103 → 0.0378 (+267%); HTTP repeats 0.0103–0.0113; HTTPS repeats 0.0339–0.0381 | 0.0114 → 0.0356 (+212%); HTTP repeats 0.0099–0.0115; HTTPS repeats 0.034–0.0382 |
| `net_bytes_per_sec_delta` | 2576 → 8366 (+225%) | 2576 → 8366 (+225%); HTTPS repeats 8114–8366 | 2576 → 8618 (+235%); HTTPS repeats 8366–8618 |
| `net_pkts_per_sec_delta` | 24 → 32 (+33%) | 24 → 32 (+33%); HTTPS repeats 28–32 | 24 → 36 (+50%); HTTPS repeats 32–36 |
| `net_down_up_ratio_delta` | 1.38 → 2.18 (+58%) | 1.38 → 2.18 (+58%); HTTPS repeats 2.18–2.24 | 1.38 → 2.12 (+54%); HTTPS repeats 2.12–2.23 |
| `net_ab_ratio_pkt_delta` | 0.583 → 0.562 (-4%) | 0.583 → 0.562 (-4%); HTTPS repeats 0.562–0.571 | 0.583 → 0.556 (-5%); HTTPS repeats 0.529–0.562 |
| `net_ba_ratio_pkt_delta` | 0.417 → 0.438 (+5%) | 0.417 → 0.438 (+5%); HTTPS repeats 0.429–0.438 | 0.417 → 0.444 (+7%); HTTPS repeats 0.438–0.471 |
| `net_ab_ratio_byte_delta` | 0.421 → 0.315 (-25%) | 0.421 → 0.315 (-25%); HTTPS repeats 0.308–0.315 | 0.421 → 0.321 (-24%); HTTPS repeats 0.31–0.321 |
| `net_ba_ratio_byte_delta` | 0.579 → 0.685 (+18%) | 0.579 → 0.685 (+18%); HTTPS repeats 0.685–0.692 | 0.579 → 0.679 (+17%); HTTPS repeats 0.679–0.69 |
| `net_syn_delta` | 2 (same) | 2 (same) | 2 (same) |
| `net_ack_delta` | 11 → 13 (+18%) | 11 → 13 (+18%); HTTPS repeats 12–13 | 11 → 14 (+27%); HTTPS repeats 13–14 |
| `net_rst_delta` | 0 → 2 | 0 → 2; HTTPS repeats 1–2 | 0 → 3; HTTPS repeats 2–3 |
| `net_flows_with_ab` | 1 (same) | 1 (same) | 1 (same) |
| `net_flows_with_ba` | 1 (same) | 1 (same) | 1 (same) |
| `net_dir_valid_count` | 1 (same) | 1 (same) | 1 (same) |

### Host features (same rows)

| host signal (max over windows; sum where marked) | amd64_dynamic | amd64_static | i386_static |
|---|---|---|---|
| `host_total_syscalls_total` (sum) | 352 → 405 (+15%) | 349 → 696 (+99%) | 338 → 892 (+164%); HTTPS repeats 887–892 |
| `host_unique_syscalls_mean` | 49 → 47 (-4%) | 55 → 54 (-2%) | 62 → 64 (+3%) |
| `host_unique_syscalls_max` | 49 → 47 (-4%) | 55 → 54 (-2%) | 62 → 64 (+3%) |
| `host_entropy_mean` | 4.13 → 4.19 (+1%) | 4 → 3.39 (-15%) | 4.51 → 3.42 (-24%); HTTPS repeats 3.41–3.42 |
| `host_entropy_max` | 4.13 → 4.19 (+1%) | 4 → 3.39 (-15%) | 4.51 → 3.42 (-24%); HTTPS repeats 3.41–3.42 |
| `host_avg_run_length_mean` | 1.82 → 1.89 (+4%) | 1.91 → 1.83 (-4%) | 1.86 → 1.4 (-25%); HTTPS repeats 1.4–1.4 |
| `host_avg_run_length_max` | 1.82 → 1.89 (+4%) | 1.91 → 1.83 (-4%) | 1.86 → 1.4 (-25%); HTTPS repeats 1.4–1.4 |
| `host_max_run_length_mean` | 54 (same) | 54 → 56 (+4%) | 54 (same) |
| `host_max_run_length_max` | 54 (same) | 54 → 56 (+4%) | 54 (same) |
| `host_transition_count_total` (sum) | 192 → 213 (+11%) | 182 → 380 (+109%) | 181 → 638 (+252%); HTTPS repeats 634–638 |
| `host_rare_syscall_ratio_mean` | 0.0426 → 0.0321 (-25%) | 0.0716 → 0.033 (-54%) | 0.0858 → 0.0325 (-62%); HTTPS repeats 0.0325–0.0327 |
| `host_rare_syscall_ratio_max` | 0.0426 → 0.0321 (-25%) | 0.0716 → 0.033 (-54%) | 0.0858 → 0.0325 (-62%); HTTPS repeats 0.0325–0.0327 |
| `host_first50_unique_mean` | 5 (same) | 5 (same) | 5 (same) |
| `host_first50_unique_max` | 5 (same) | 5 (same) | 5 (same) |
| `host_first100_unique_mean` | 15 (same) | 15 (same) | 15 (same) |
| `host_first100_unique_max` | 15 (same) | 15 (same) | 15 (same) |
| `host_top_syscall_freq_mean` | 0.315 → 0.274 (-13%) | 0.327 → 0.279 (-15%) | 0.237 → 0.298 (+26%); HTTPS repeats 0.298–0.3 |
| `host_top_syscall_freq_max` | 0.315 → 0.274 (-13%) | 0.327 → 0.279 (-15%) | 0.237 → 0.298 (+26%); HTTPS repeats 0.298–0.3 |

Where the host change comes from (raw system calls of the `curl` process, dataset rows):

| mode | curl system calls | largest changes (HTTPS − HTTP) |
|---|---|---|
| amd64_dynamic | 174 → 227 | read +24, getpid +14, brk +5, poll +4, write +4, futex +3 |
| amd64_static | 171 → 518 | mmap +148, munmap +148, read +24, getpid +14, poll +4, write +4 |
| i386_static | 160 → 714 | mmap2 +239, munmap +238, madvise +26, read +24, getpid +14, rt_sigprocmask +4 |

### Shift against repeats and against other harmless changes

Per contrast: columns that change at all / columns whose two sets of repeats do not overlap; `D` = Euclidean distance
between the two means with every column divided by its SD over the 240 dataset rows (145 network or 90 host columns);
`D repeats` = mean distance between two repeats of one task; `perm p` = exact permutation p-value of the network `D`
over all relabelings of the runs (only with at least 3 runs per side; 0.0079 is the smallest possible with 5 + 5).

| contrast | mode | runs | net changed / separated | net D | net D repeats | net perm p | host changed / separated | host D | host D repeats |
|---|---|---|---|---|---|---|---|---|---|
| **transport** | amd64_dynamic | 2/2 | 97 / 97 | 3.91 | 0.00069 | - | 48 / 48 | 0.54 | 0 |
| **transport** | amd64_static | 5/5 | 97 / 97 | 4.23 | 0.25 | 0.0079 | 56 / 56 | 0.95 | 0 |
| **transport** | i386_static | 5/5 | 97 / 97 | 3.68 | 0.2 | 0.0079 | 48 / 48 | 1.66 | 0.0037 |
| options | amd64_dynamic | 2/3 | 24 / 0 | 0.00 | 0.00052 | - | 50 / 44 | 1.71 | 0.013 |
| program | amd64_dynamic | 2/2 | 40 / 40 | 0.20 | 0.00033 | - | 56 / 56 | 1.48 | 0 |
| program | amd64_static | 5/5 | 40 / 32 | 0.20 | 0.00038 | 0.0079 | 56 / 56 | 1.88 | 0 |
| program | i386_static | 5/5 | 40 / 32 | 0.20 | 0.00035 | 0.0079 | 56 / 56 | 1.52 | 0 |
| request:post | amd64_static | 5/3 | 55 / 40 | 0.31 | 0.00021 | 0.018 | 44 / 0 | 0.01 | 0.0045 |
| request:post | i386_static | 5/3 | 55 / 40 | 0.31 | 0.00036 | 0.018 | 16 / 0 | 0.00 | 0 |
| request:headers | amd64_static | 5/3 | 55 / 32 | 0.03 | 0.00022 | 0.018 | 44 / 40 | 0.11 | 0 |
| request:headers | i386_static | 5/3 | 55 / 32 | 0.03 | 0.00032 | 0.018 | 44 / 40 | 0.09 | 0 |
| request:index | i386_static | 5/3 | 55 / 32 | 0.04 | 0.00037 | 0.018 | 16 / 0 | 0.00 | 0 |
| url | amd64_dynamic | 2/2 | 40 / 40 | 0.01 | 0.00037 | - | 0 / 0 | 0.00 | 0 |
| url | amd64_static | 5/5 | 40 / 32 | 0.01 | 0.00039 | 0.0079 | 0 / 0 | 0.00 | 0 |
| url | i386_static | 5/5 | 40 / 32 | 0.01 | 0.00049 | 0.0079 | 0 / 0 | 0.00 | 0 |
| tls-option | amd64_dynamic | 2/2 | 64 / 36 | 0.54 | 0.18 | - | 28 / 28 | 0.02 | 0 |
| tls-option | amd64_static | 5/5 | 72 / 20 | 0.45 | 0.24 | 0.0079 | 40 / 40 | 0.02 | 0 |
| tls-option | i386_static | 5/3 | 82 / 28 | 0.38 | 0.59 | 0.48 | 44 / 8 | 0.01 | 0.014 |
| port (telnet 58da93ec) | amd64_static | 2/2 | 65 / 65 | 0.64 | 0.00073 | - | 0 / 0 | 0.00 | 0 |
| port (telnet adcf3ee0) | amd64_static | 2/2 | 65 / 65 | 0.64 | 0.00044 | - | 0 / 0 | 0.00 | 0 |
| port (telnet e2518af2) | i386_static | 3/3 | 65 / 65 | 0.64 | 0.00063 | 0.1 | 0 / 0 | 0.00 | 0 |

The telnet rows are a control: port 80 vs 443 is a bare TCP connect either way (no TLS from the client); the lab's TLS
service answers with a 7-byte alert, the HTTP service does not, which alone moves 65 columns by 0.64.

### Detector decisions (Table V protocol: out-of-fold for the dataset rows, the same fold models for the repeats)

| mode | detector | flag rate HTTP → HTTPS | mean p HTTP → HTTPS | decision changes, HTTP vs HTTPS pairs | decision changes, repeat pairs |
|---|---|---|---|---|---|
| amd64_dynamic | host | 0.70 → 0.70 | 0.609 → 0.537 | 8/40 | 0/20 |
| amd64_dynamic | network | 0.00 → 0.00 | 0.079 → 0.022 | 0/40 | 0/20 |
| amd64_dynamic | concat | 0.20 → 0.10 | 0.380 → 0.280 | 4/40 | 0/20 |
| amd64_dynamic | stacked | 0.30 → 0.20 | 0.341 → 0.284 | 4/40 | 0/20 |
| amd64_static | host | 0.50 → 0.10 | 0.465 → 0.231 | 100/250 | 0/200 |
| amd64_static | network | 0.00 → 0.00 | 0.079 → 0.021 | 0/250 | 0/200 |
| amd64_static | concat | 0.00 → 0.10 | 0.304 → 0.147 | 25/250 | 0/200 |
| amd64_static | stacked | 0.00 → 0.00 | 0.262 → 0.146 | 0/250 | 0/200 |
| i386_static | host | 0.30 → 0.00 | 0.411 → 0.222 | 75/250 | 0/200 |
| i386_static | network | 0.00 → 0.00 | 0.079 → 0.023 | 0/250 | 0/200 |
| i386_static | concat | 0.10 → 0.00 | 0.305 → 0.128 | 25/250 | 0/200 |
| i386_static | stacked | 0.10 → 0.00 | 0.243 → 0.134 | 25/250 | 0/200 |

Pooled over the three builds, against pairs of runs that differ in something else (all pairs scored by the same fold
model; every count is pairs × fold assignments, and repeats are near-identical, so the effective sample is three builds
× ten assignments):

| pairs of runs | host | network | concat | stacked |
|---|---|---|---|---|
| **HTTP → HTTPS (transport)** | **183/540** | **0/540** | **54/540** | **29/540** |
| repeats of one task (all transport repeats) | 0/420 | 0/420 | 0/420 | 0/420 |
| curl → wget (same GET /) | 195/540 | 0/540 | 29/540 | 33/540 |
| curl -s → progress meter on | 42/60 | 0/60 | 12/60 | 18/60 |
| GET / → GET /headers -D | 45/300 | 0/300 | 0/300 | 0/300 |
| GET / → POST /submit | 10/300 | 0/300 | 0/300 | 0/300 |
| wget GET / → GET /data | 0/540 | 0/540 | 0/540 | 0/540 |
| openssl SNI → -tls1_3 (TLS both) | 0/440 | 0/440 | 0/440 | 6/440 |

Flag rate by transport over all runs (fraction of runs × assignments). The TLS runs are flagged no more often than
the cleartext ones by any detector; the only class the network detector flags is the bare TCP connect (telnet):

| runs | n | host | network | concat | stacked |
|---|---|---|---|---|---|
| cleartext HTTP tasks (curl, wget) | 63 (9 dataset rows) | 0.32 | 0.00 | 0.08 | 0.04 |
| curl over HTTPS | 12 (3 dataset rows) | 0.16 | 0.00 | 0.06 | 0.03 |
| openssl s_client (TLS) | 25 (5 dataset rows) | 0.13 | 0.00 | 0.06 | 0.04 |
| telnet (TCP connect, no TLS) | 14 (4 dataset rows) | 0.14 | 0.38 | 0.17 | 0.21 |
| *reference: all 105 dataset benign rows (Table V OOF)* | 105 | 0.15 | 0.02 | 0.11 | 0.10 |

## 2. Sliver implants: HTTP vs HTTPS vs mutual TLS

### Runs (as captured; `pos` = position in the collection order)

| implant | pos | transport (tshark, 5 min) | 20 s: TCP conn / TLS handshakes / HTTP requests | 20 s: packets / bytes | 5 min: TCP conn / TLS / HTTP | 5 min: packets / bytes | host calls 20 s / 5 min | stray WG pkts 20 s / 5 min | rc |
|---|---|---|---|---|---|---|---|---|---|
| `lab-http-beacon-a` | 22 | HTTP cleartext; 1 TLS ClientHello without ServerHello | 7 / 0 / 9 | 76 / 15776 | 63 / 0 / 111 | 737 / 169798 | 2631 / 20405 | 0 / 0 | -15 |
| `lab-http-beacon-b` | 24 | HTTP cleartext; 1 TLS ClientHello without ServerHello | 6 / 0 / 9 | 72 / 26223 | 62 / 0 / 110 | 733 / 190019 | 2609 / 20403 | 0 / 0 | -15 |
| `lab-https-beacon-a` | 8 | TLS1.3 | 5 / 5 / 0 | 94 / 36109 | 61 / 61 / 0 | 1183 / 446789 | 2571 / 20713 | 0 / 0 | -15 |
| `lab-https-beacon-b` | 18 | TLS1.3 | 6 / 6 / 0 | 122 / 50557 | 62 / 62 / 0 | 1260 / 465115 | 2716 / 22115 | 4 / 52 | -15 |
| `lab-mtls-beacon-a` | 20 | TLS1.3 | 5 / 5 / 0 | 160 / 36119 | 61 / 61 / 0 | 1981 / 442837 | 2646 / 22800 | 0 / 0 | -15 |
| `lab-mtls-beacon-b` | 6 | TLS1.3 | 5 / 5 / 0 | 152 / 35865 | 61 / 61 / 0 | 1990 / 446803 | 2621 / 24154 | 0 / 0 | -15 |
| `lab-mtls-session-a` | 14 | TLS1.3 | 1 / 1 / 0 | 174 / 24049 | 1 / 1 / 0 | 2038 / 234900 | 2563 / 20595 | 0 / 0 | -15 |
| `lab-mtls-session-b` | 4 | TLS1.3 | 1 / 1 / 0 | 177 / 24351 | 1 / 1 / 0 | 1986 / 231602 | 2752 / 20770 | 0 / 0 | -15 |
| `lab-wg-session-a` | 26 | UDP | 0 / 0 / 0 | 228 / 37496 | 0 / 0 / 0 | 2517 / 413106 | 4055 / 28992 | 0 / 0 | -15 |
| `lab-wg-session-b` | 16 | UDP | 0 / 0 / 0 | 226 / 37348 | 0 / 0 / 0 | 2393 / 398410 | 3747 / 27647 | 0 / 0 | -15 |
| `lab-wg-beacon-a` | 10 | none | 0 / 0 / 0 | 0 / 0 | 0 / 0 / 0 | 0 / 0 | 795 / 795 | 0 / 0 | 2 |
| `lab-wg-beacon-b` | 12 | none | 0 / 0 / 0 | 0 / 0 | 0 / 0 / 0 | 0 / 0 | 815 / 815 | 0 / 0 | 2 |

The HTTP transport carries Sliver's own encrypted, encoded messages in cleartext HTTP requests (one POST body even
starts like a PNG file) and begins with one TLS ClientHello (1495 B) that the HTTP listener rejects (HTTP 400)
before falling back to HTTP. In the HTTPS and mTLS beacons the RSTs come from the Go client, not the server. The WireGuard beacons exited
(status 2) without traffic and are not compared.

### Stray WireGuard packets

| pos | run | kind | stray WG packets, first 20 s | 5 min |
|---|---|---|---|---|
| 17 | `native_amd64_dynamic-git-git-hold-ip` | benign | 5 | 57 |
| 18 | `lab-https-beacon-b` | https-beacon | 4 | 52 |
| 19 | `native_amd64_dynamic-rsync-rsync-timeout60` | benign | 2 | 20 |
| 27 | `native_amd64_dynamic-curl-curl-oneshot-host` | benign | 5 | 57 |

### Totals per implant (`a / b`; switch features without the stray packets)

| signal | 20 s HTTP | 20 s HTTPS | 20 s mTLS | 5 min HTTP | 5 min HTTPS | 5 min mTLS |
|---|---|---|---|---|---|---|
| packets (`net_pkts_total_delta`, sum) | 76 / 72 | 94 / 118 | 152 / 160 | 737 / 733 | 1183 / 1208 | 1990 / 1981 |
| bytes (`net_bytes_total_delta`, sum) | 15776 / 26223 | 36109 / 49797 | 35865 / 36119 | 169798 / 190019 | 446789 / 455235 | 446803 / 442837 |
| bytes guest → server (`net_bytes_ab_delta`, sum) | 10714 / 21315 | 18434 / 24382 | 20218 / 19944 | 101517 / 123066 | 211541 / 223328 | 248175 / 242170 |
| bytes server → guest (`net_bytes_ba_delta`, sum) | 5062 / 4908 | 17675 / 25415 | 15647 / 16175 | 68281 / 66953 | 235248 / 231907 | 198628 / 200667 |
| SYN (≈ 2 per connection) (`net_syn_delta`, sum) | 14 / 12 | 10 / 12 | 10 / 10 | 126 / 124 | 122 / 124 | 122 / 122 |
| RST (`net_rst_delta`, sum) | 0 / 0 | 9 / 12 | 11 / 10 | 0 / 0 | 125 / 129 | 123 / 124 |
| flow-windows (flows × windows active) (`net_flow_count_seen`, sum) | 28 / 24 | 20 / 24 | 30 / 30 | 252 / 248 | 244 / 248 | 366 / 366 |
| longest flow, s (`net_flow_duration_max`, max) | 0.013 / 0.01 | 0.012 / 0.013 | 1.022 / 1.014 | 0.052 / 0.023 | 0.112 / 0.035 | 1.03 / 1.032 |
| largest frame, B (`net_max_len_max`, max) | 1561 / 4630 | 2415 / 2566 | 2054 / 2054 | 4967 / 4944 | 5365 / 5392 | 2054 / 2054 |
| host system calls (`host_total_syscalls_total`, sum) | 2631 / 2609 | 2571 / 2716 | 2621 / 2646 | 20405 / 20403 | 20713 / 22115 | 24154 / 22800 |
| host entropy (per-window mean) (`host_entropy_mean`, mean) | 0.591 / 0.588 | 0.608 / 0.584 | 0.685 / 0.669 | 0.511 / 0.513 | 0.508 / 0.504 | 0.57 / 0.575 |

Frames larger than 1,514 B are TCP segmentation/receive-offload frames seen by the guest-side capture; a switch would
see them split. They occur in every transport.

### Shift against the a/b spread (without the stray packets; scale = column SD over the testbed's 27 runs)

| length | role | contrast | net D | net D a/b | net cols > both a/b diffs | host D | host D a/b | host cols > both a/b diffs |
|---|---|---|---|---|---|---|---|---|
| 20s | transport | http-beacon vs https-beacon | 10.9 | 7.9 | 54 | 1.9 | 2.8 | 7 |
| 20s | transport | http-beacon vs mtls-beacon | 13.4 | 5.5 | 114 | 4.2 | 2.6 | 38 |
| 20s | transport | https-beacon vs mtls-beacon | 9.8 | 3.8 | 93 | 4.4 | 2.4 | 38 |
| 20s | reference | mtls-beacon vs mtls-session | 18.5 | 3.3 | 124 | 12.7 | 6.1 | 60 |
| 20s | reference | mtls-session vs wg-session | 12.8 | 4.6 | 107 | 4.9 | 6.9 | 41 |
| 5min | transport | http-beacon vs https-beacon | 9.8 | 2.6 | 78 | 2.5 | 2.5 | 25 |
| 5min | transport | http-beacon vs mtls-beacon | 15.0 | 1.5 | 137 | 4.1 | 3.1 | 53 |
| 5min | transport | https-beacon vs mtls-beacon | 11.1 | 1.4 | 114 | 4.2 | 2.6 | 49 |
| 5min | reference | mtls-beacon vs mtls-session | 20.7 | 0.6 | 135 | 14.6 | 4.4 | 76 |
| 5min | reference | mtls-session vs wg-session | 10.1 | 0.9 | 114 | 5.4 | 3.9 | 79 |

### Detector decisions (trained on all 240 dataset rows, applied to the first 40 windows)

| variant | implant | host | network | concat | stacked |
|---|---|---|---|---|---|
| as collected | `lab-http-beacon-a` | 0.918 ✓ | 0.240 | 0.578 ✓ | 0.600 ✓ |
| as collected | `lab-http-beacon-b` | 0.920 ✓ | 0.236 | 0.590 ✓ | 0.598 ✓ |
| as collected | `lab-https-beacon-a` | 0.916 ✓ | 0.142 | 0.558 ✓ | 0.511 ✓ |
| as collected | `lab-https-beacon-b` | 0.928 ✓ | 0.644 ✓ | 0.716 ✓ | 0.869 ✓ |
| as collected | `lab-mtls-beacon-a` | 0.908 ✓ | 0.388 | 0.598 ✓ | 0.714 ✓ |
| as collected | `lab-mtls-beacon-b` | 0.906 ✓ | 0.394 | 0.586 ✓ | 0.717 ✓ |
| without stray wireguard | `lab-http-beacon-a` | 0.918 ✓ | 0.240 | 0.578 ✓ | 0.600 ✓ |
| without stray wireguard | `lab-http-beacon-b` | 0.920 ✓ | 0.236 | 0.590 ✓ | 0.598 ✓ |
| without stray wireguard | `lab-https-beacon-a` | 0.916 ✓ | 0.142 | 0.558 ✓ | 0.511 ✓ |
| without stray wireguard | `lab-https-beacon-b` | 0.928 ✓ | 0.154 | 0.556 ✓ | 0.530 ✓ |
| without stray wireguard | `lab-mtls-beacon-a` | 0.908 ✓ | 0.388 | 0.598 ✓ | 0.714 ✓ |
| without stray wireguard | `lab-mtls-beacon-b` | 0.906 ✓ | 0.394 | 0.586 ✓ | 0.717 ✓ |

| variant | host | network | concat | stacked |
|---|---|---|---|---|
| as collected | 6/6 beacons; 6/12 benign | 1/6 beacons; 5/12 benign | 6/6 beacons; 5/12 benign | 6/6 beacons; 6/12 benign |
| without stray wireguard | 6/6 beacons; 6/12 benign | 0/6 beacons; 2/12 benign | 6/6 beacons; 2/12 benign | 6/6 beacons; 4/12 benign |

Every consecutive 20-s block of the 5-min runs (15 per implant, 30 per transport; blocks after the first lack the
process start, so host and hybrid scores there are outside the training conditions):

| variant | runs | host | network | concat | stacked |
|---|---|---|---|---|---|
| as collected | http-beacon | 1.00 | 0.00 | 1.00 | 0.93 |
| as collected | https-beacon | 1.00 | 0.50 | 1.00 | 0.97 |
| as collected | mtls-beacon | 1.00 | 0.00 | 1.00 | 1.00 |
| as collected | benign | 0.44 | 0.34 | 0.51 | 0.37 |
| without stray wireguard | http-beacon | 1.00 | 0.00 | 1.00 | 0.93 |
| without stray wireguard | https-beacon | 1.00 | 0.00 | 1.00 | 0.90 |
| without stray wireguard | mtls-beacon | 1.00 | 0.00 | 1.00 | 1.00 |
| without stray wireguard | benign | 0.44 | 0.16 | 0.33 | 0.21 |

## 3. Caveats

1. The paired dataset evidence is one program (curl, three builds) making one tiny request. One-shot requests carry the
   largest relative TLS overhead; long sessions dilute it. The cross-program groups (wget, openssl, telnet) differ in
   more than the transport.
2. Only TLS 1.3 occurs (every ServerHello negotiates 0x0304). The handshake size depends on the stack and options:
   ClientHello 517 B for curl, 316 B for `s_client` with SNI, 225 B for `s_client -tls1_3` (OpenSSL 3.0, X25519), 1495 B
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

Gates (all asserted by the scripts): the cached Table V out-of-fold probabilities reproduce host 0.784 / network
0.756 / stacked 0.823 (mean of ten fold assignments); the 26 refit fold models reproduce those cached
probabilities for the dataset rows exactly (max difference 0); every dataset row rebuilt from its run equals
`features.csv`; tshark's in-window IPv4 TCP/UDP packet and byte counts equal the switch features of every run; the
release switch model reproduces the Sliver runs' collected switch features exactly; the as-collected Sliver scores
reproduce the saved `analysis/sliver_results.json`.

| file | SHA-256 |
|---|---|
| `wire.py` | `e9eb5397d2fc72e98063769b0f60d7c6c008c5344a43c4c524d6909af2c25238` |
| `contrast.py` | `e1b0ddf510a199bd4a3efe14addf3648c3e94ffe2492228483cf8b760093b8c0` |
| `dataset_http_https.py` | `d85ca801fef7decc6332cd1047f2d2977b8d1ede2979f2bfdb6452b5378f267f` |
| `sliver_transports.py` | `85c0c2e5278c5616483593c4078c9d3d44faa44462df4387c6ad24b580892e4f` |
| `report.py` | `17d014793f12482b6ae1a8d5e149f391c0a1a3477704318edb1bc10ae829b6f5` |
| `results_dataset.json` | `23216472f90a38720c032e3d50782aada101f89d73dbd5ccf93912fc4baf8b13` |
| `results_sliver.json` | `17a24fafaa12e6380d228304c6f33270211772115ab9cbfddef0d6068b5b338e` |
| `columns_dataset.csv` | `b626d9495ed25bfcdb805b22d928917fe9163aea3bf543e7fc5efa810eeee844` |
| `dataset_http_https.log` | `2b95d86a64260747936e7072171301c5f616e1997c693213bcfefcc0580dfe96` |
| `sliver_transports.log` | `a00e42a97b4be0b2e561180310a35e95efd18bebbfb69a9113529adb7e2b3ded` |
| `results.json` | `e74bfed0b2572068f4263c3f443ef1661c303f9d464d826208e930a409251248` |
| `tables.md` | `545418c0158282f526962e7604148a7d7ae4a6dd67d1e0df064ac9af64c9aef9` |
| input `features.csv` | `6d15da30a4bc1b9bcea47bce1b96c00f74ae5ddadd68255a17ed5d0b46c19c16` |
| input `cache/cv_published_k40.npz` | `3fc9937be82735eaff537f2913667db96e62181f7e13b00ce95f07dd8ecaa905` |
| input `switch_model.py` | `d5a140fd5cda04afc9e6d73a28da354146ed184c9b381ca4d89a20543791eb80` |
| input `sliver protocol.json` | `84e900940ac4cf1c857899f837fd20436fbbab2aad3d57dd6c8d8b70b1ee623d` |
