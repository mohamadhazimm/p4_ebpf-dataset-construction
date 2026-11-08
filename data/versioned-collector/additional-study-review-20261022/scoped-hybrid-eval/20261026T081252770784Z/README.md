# Scoped hybrid evaluation — pooled paired host+network captures (offline, no VM)

Written for: the thesis author, as the numeric basis for the scoped hybrid claim. 2026-10-26.

## What was pooled
62 real sandbox runs that each have BOTH a host syscall trace and a packet capture:
precision-phase4 (flood, host-storm malware, benign bulk, null), c2-viability (Meterpreter
reverse shells, Sliver/CobaltStrike/Winnti/Merlin beacons, nulls), evasive-viability
(Rekoobe, BPFDoor, nulls); plus 4 phase-3 scanner-flood PCAPs (network-only).
Network flow-shape parsed uniformly from every PCAP; host features from a per-sample syscall histogram.
Reproduce: `/usr/bin/python3 pool_scoped_hybrid.py` then the aggregation snippets; outputs here.

## Correction 1 — a trained pooled classifier is NOT valid on this data
Leave-one-group-out malicious-vs-benign degenerates (every model tn=0, flags all benign as
malicious) because the benign side has only two groups (bulk, quiet) and holding each out
leaves no representative benign example. Tiny n + near-duplicate malware families compound it.
The fitted numbers are an artifact and are NOT used.

## Correction 2 — the host-evasive reverse-shell claim does NOT survive the captured data
The viability probes' `inwindow_net` ~740 does NOT equal the captured wire. run.json
`packets_captured` and the PCAP itself show 11-23 enp0s3 frames for EVERY reverse shell /
beacon / backdoor (Meterpreter 21-23, Sliver 16-22, Rekoobe 11-23, BPFDoor 12-13) — barely
above a quiet null (~12). Against the FAKE Sink (which can't speak their C2 protocol) their
connections failed, so they were network-near-silent on the wire. So there is NO
"host-quiet + network-loud" case in the captured data; the host-evasive numeric claim is
retracted. (It would need a live/emulated C2 — PhD-expansion work.)

## Result that DOES hold — flood detection on real captures
Floods = 5 (1 phase-4 Kaiten SYN-flood + 4 phase-3 scanner floods). Hard negatives = 6 benign
high-volume downloads (curl/wget/openssl/python to the Sink). Both classes are HOST-loud
(flood 19.2M syscalls; benign bulk 0.77-4.72M), so host activity cannot separate them.

| Detector | recall | specificity | precision | BA | confusion |
|---|---|---|---|---|---|
| Host activity (syscall volume) | 1.00 (1/1) | 0.00 (0/6) | 0.14 | 0.50 | flags all 6 benign downloads as attacks |
| Network flow-shape | 1.00 (5/5) | 1.00 (6/6) | 1.00 | 1.00 | tp5 fn0 fp0 tn6 |

Flood flow-shape signature (SYN-only frac, handshake completed, distinct dst IPs):
flood = SYN-only 1.00 / 0 handshakes / 11k-70k distinct dst; benign bulk = SYN-only 0.08 /
handshake 6/6 / 1 dst. Categorical separation.

## Why the hybrid still needs the host half (complementarity)
Network-silent host-storm malware (gafgyt_a host 828,713 syscalls / 11 packets; mirai_a 834,275 /
25 packets) is MISSED by the network flood detector and caught by the host half. So: host half
detects host-active malware; network half detects floods and refuses to false-alarm on benign bulk.

## Backbone number (separate, big-n): CIC-DDoS2019
Network flow features detect all 7 DDoS types at BA 0.998-1.000 (see cic-ddos-sweep/). That is
the generalization evidence for the network half; the sandbox table above is the mechanism on
real paired captures.
