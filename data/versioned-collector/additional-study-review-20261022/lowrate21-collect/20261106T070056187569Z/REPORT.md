# Low-rate benign background traffic: collection and re-tests

Step 1 of the IoT-23 follow-ups. The IoT-23 check showed that the paper's network-only detector flags
57% of benign IoT-device chunks, because no benign training row has low-rate background traffic.
This run adds such rows and re-tests. The protocol was fixed before collection (`collect_lowrate21.py`,
`score_lowrate21.py`).

## Collection

- Benign only: 18 runs of `lowrate_gen` (SHA `37f8c12f...`). Every run talks only to the Sink
  10.0.0.1. Activities are HTTP polls, HTTP keepalives, DNS, NTP, TLS polls and TLS keepalives every
  1 to 10 s, plus three mixed "device" profiles. Each run exits on its own after 19 s.
- Real collector on the quiet baseline `clean-final-quiet-v19-20261024T150104720304Z`. New child
  `clean-lowrate21-20261106T070056187569Z` (UUID `052498aa...`). One batch, 20 s fixed observation,
  0.5-s windows. Started 2026-11-06 07:00 UTC, finished 07:18 UTC.
- Runner: the installed `.22` (`b6d7abb9...`), which is `.21` plus a cap on retained eBPF events.
  No run came near the cap (overflow 0), so features and their computation are those of `.21`.
- One boot hung, on case 17 (`lr_device_b`). The batch restarted the VM once, and the case completed.
  The original snapshot `clean-tls-paired-2026-10-19` was restored, the guest powered off, and only
  the Sink was left running.

## Checks

All 18 runs pass:

- collector quality accepted, target exec observed, exit 0, 40 windows;
- eBPF loss 0, overflow 0;
- tcpdump received = captured = frames in the pcap, kernel drops 0.

Every IP frame is between the guest and the Sink; the remaining frames are ARP. The P4 packet count
of every run equals its guest-Sink frames minus the 8 capture-path probe frames, which lie outside
the windows. The NTP runs are the exception: they also differ by their ICMP replies, which are not
TCP/UDP.

The Sink does not answer NTP. All NTP requests got ICMP port-unreachable replies, and no NTP answer
came back. The rule fixed before collection requires an answer for every activity a run did, so four
runs are excluded: `lr_ntp_2s`, `lr_ntp_8s`, `lr_device_a` and `lr_device_c`. That leaves 14 rows:

| Kind | Rows |
|---|---:|
| poll | 4 |
| keepalive | 3 |
| dns | 3 |
| tlspoll | 2 |
| tlskeep | 1 |
| device_b | 1 |

Both baselines reproduce the earlier results. The IoT-23 transfer result matches the earlier run
(self-test True). The Table V run without the new rows gives host 0.784, network 0.756 and hybrid
0.823. These match `combined-surface-expanded/20261027T165348Z/expanded_cv.json` to its stored three
decimals; the SDs differ by at most 0.0005, because that file rounds its per-seed values.

## T1: IoT-23, network-only detector retrained with the 14 rows

Same model and chunks as `iot23-external/runs/20261105T202318Z`. Flagged fraction at threshold 0.5:

| IoT-23 group | 240 rows | 240 + 14 low-rate |
|---|---:|---:|
| DDoS (349 chunks) | 100.0% | 100.0% |
| Scan (1,003) | 99.9% | 97.1% |
| Attack (8) | 100.0% | 100.0% |
| C&C only (1,491), mean over scenarios | 79.2% | 65.7% |
| Infected, quiet (566) | 86.8% | 74.1% |
| Benign Hue (600) | 39.5% | 36.0% |
| Benign Echo (600) | 89.2% | 76.3% |
| Benign Somfy (600) | 42.0% | 0.7% |
| Benign devices, mean | 56.9% | 37.7% |

AUC against the benign devices rose for every group:

| Group | 240 rows | 240 + 14 low-rate |
|---|---:|---:|
| DDoS | 0.944 | 0.971 |
| Scan | 0.883 | 0.938 |
| Attack | 0.971 | 0.994 |
| C&C | 0.767 | 0.805 |

Balanced accuracy, DDoS vs benign devices, went from 0.716 to 0.812.

Median per 20-s chunk:

| Group | Packets | Flows | Active windows |
|---|---:|---:|---:|
| Somfy | 23 | 1 | 4 |
| New low-rate rows | 43 | 1 | 6 |
| Echo | 5 | 2 | 4 |
| Hue | 2 | 1 | 1 |
| Dataset malware | 8 | 1 | 2 |

The new rows fixed the device they resemble (Somfy). Hue and Echo chunks carry fewer packets than
the dataset's network-quiet malware, so a 20-s network window cannot separate them.

## T2: the paper's combined evaluation (Table V procedure, 10 fold assignments)

The 14 rows are added as benign, with one CV group per activity kind. Scores below are on the
original 240 rows only, from the per-category out-of-fold rates. Balanced accuracy:

| Detector | 240 rows | 254 rows, scored on the original 240 |
|---|---:|---:|
| Host only | 0.784 | 0.808 |
| Network only | 0.756 | 0.774 |
| Hybrid | 0.823 | 0.847 |

Scored on all 254 rows, the second column reads 0.814, 0.764 and 0.846. Per category, flagged
fraction, 240 rows → 254 rows:

| Category | Host | Network | Hybrid |
|---|---|---|---|
| Malware (99) | .715 → .709 | .520 → .508 | .739 → .762 |
| DoS attacks (15) | .940 → .920 | .987 → .933 | .993 → .980 |
| CLI benign (105) | .154 → .117 | .023 → .004 | .095 → .081 |
| Network-active benign (18) | .183 → .000 | .350 → .083 | .178 → .033 |
| Null (3) | .9 → 1.0 | 0 → 0 | .9 → 1.0 |
| New low-rate rows (14) | 0 | .221 | .114 |

## Reading

Adding low-rate benign rows to training cuts the network detector's false alarms on benign IoT
devices by a third (57% to 38% of chunks). Floods and attacks are caught as before, and its ranking
improves for every IoT-23 group. The price at threshold 0.5 is fewer flagged C&C-only and quiet
infected chunks; those chunks look like the new benign traffic.

In the paper's own evaluation, every detector does slightly better on the original rows, mostly
through fewer false alarms on the 18 network-active benign controls. The paper's numbers are
unchanged; this is an additional result.

## Limits

- 14 rows from one self-built generator, with 7 activity kinds and periods of 1 to 10 s.
- CV groups are by activity kind, but all rows share the binary. The host model may recognize the
  binary or its build: the host flags none of the 14 rows, and its false alarms on the 18 self-built
  network-active controls drop to 0. Discount host-side gains accordingly.
- T2 runs with and without the rows use different fold splits (adding groups changes them), so the
  comparison is not paired by fold. The hybrid SD over assignments is 0.015-0.022, so the 0.024 gain
  is about 2.8 standard errors of the 10-assignment mean.
- NTP could not be tested because the Sink does not serve it.
- IoT-23 is network-only, and T1 retrains only the network detector, as the IoT-23 protocol did.
- Hue and Echo remain open; their chunks are too quiet for a 20-s window.

## Files

- `scoring.json` (SHA `f7cd5cdd...`)
- `lowrate_rows.csv` (SHA `b7a1dbb8...`; the 14 rows in the dataset's 235 columns)
- `protocol.json` (SHA `f3117eca...`)
- `scoring-console.log`
- `run/` (authorization, stage and collection logs, initial and final VM state)
