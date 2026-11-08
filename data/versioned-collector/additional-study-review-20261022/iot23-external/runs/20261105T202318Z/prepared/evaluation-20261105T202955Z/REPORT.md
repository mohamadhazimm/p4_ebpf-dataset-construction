# IoT-23 external check of the switch features

Generated 2026-11-05 20:31 UTC from `evaluation-20261105T202955Z`
(protocol SHA-256 `1d5885bc4415c7bb87dc62e10aa708265d869c265082c4afeb10e72dc54f90a4`, release repository commit `3e7cb5f10a2b`).

Offline analysis of public packet captures. No virtual machine, no sample execution; the IoT-23 malware
binaries were never downloaded (only pcaps, labeled Zeek connection logs and READMEs).

## What was tested

IoT-23 (Stratosphere Laboratory, CC BY 4.0) has captures of real Linux IoT malware running on a
Raspberry Pi with Internet access, with per-flow labels, and captures of three benign IoT devices.
Every capture was cut into consecutive 20-s chunks. Each chunk is one observation in the dataset's
format: 40 windows of 0.5 s, the 29 window features of the switch model (`features/switch_model.py`,
fresh flow table per chunk), summarized into the 145 network columns (`features/summary.py`). A chunk's
category is the highest-priority label among the flows that overlap it (DDoS > scan > attack > C&C >
other > benign > none). At most 200 chunks per category and capture file were drawn with a fixed seed;
benign devices contribute 600 chunks each.

* **A. Transfer (primary).** The paper's network-only detector (random forest, 500 trees, balanced
  class weights, seed 42) trained on all 240 rows of `dataset/features.csv`, applied unchanged.
  Flagged = malicious probability >= 0.5.
* **B. Within IoT-23 (secondary).** The same random forest trained on IoT-23 chunks with
  leave-one-scenario-out folds (attack and C&C chunks vs benign-device chunks).

Fractions are computed per scenario and then averaged, so each capture counts once.

## Data

| Scenario | Family | Role | File | Hours | Frames | Chunks by category (all) | Sampled |
|---|---|---|---|---:|---:|---|---:|
| Honeypot-Capture-4-1 | Philips Hue | benign | 2018-10-25-14-06-32-192.168.1.132.pcap | 21.9 | 21664 | benign 3942 | 600 |
| Honeypot-Capture-5-1 | Amazon Echo | benign | 2018-09-21-capture.pcap | 5.5 | 398313 | benign 987 | 600 |
| Honeypot-Capture-7-1 | Somfy door lock | benign | Somfy-01/2019-07-03-15-15-47-first_start_somfy_gateway.pcap | 1.4 | 8276 | benign 240, idle 14 | 114 |
| Honeypot-Capture-7-1 | Somfy door lock | benign | Somfy-02/2019-07-03-16-41-09-192.168.1.158.pcap | 24.0 | 119638 | benign 4319 | 100 |
| Honeypot-Capture-7-1 | Somfy door lock | benign | Somfy-03/2019-07-04-16-41-10-192.168.1.158.pcap | 12.3 | 62851 | benign 2216 | 100 |
| Honeypot-Capture-7-1 | Somfy door lock | benign | Somfy-04/2019-07-05-16-41-14-192.168.1.158.pcap | 24.0 | 121554 | benign 4319 | 100 |
| Honeypot-Capture-7-1 | Somfy door lock | benign | Somfy-05/2019-07-06-16-41-17-192.168.1.158.pcap | 24.0 | 121566 | benign 4319 | 100 |
| Honeypot-Capture-7-1 | Somfy door lock | benign | Somfy-06/2019-07-07-16-41-19-192.168.1.158.pcap | 24.0 | 119158 | benign 4319 | 100 |
| IoT-Malware-Capture-1-1 | Hide and Seek | malware | 2018-05-09-192.168.100.103.pcap | 111.9 | 1686291 | scan 20142 | 200 |
| IoT-Malware-Capture-20-1 | Torii | malware | 2018-10-02-13-12-30-192.168.100.103.pcap | 24.0 | 50156 | benign 21, cc 4296, idle 1 | 222 |
| IoT-Malware-Capture-21-1 | Torii | malware | 2018-10-03-15-22-32-192.168.100.113.pcap | 24.0 | 50277 | benign 22, cc 4296, idle 1 | 223 |
| IoT-Malware-Capture-3-1 | Muhstik | malware | 2018-05-21_capture.pcap | 36.1 | 496959 | benign 1, idle 88, scan 6413 | 221 |
| IoT-Malware-Capture-34-1 | Mirai | malware | 2018-12-21-15-50-14-192.168.1.195.pcap | 24.0 | 233865 | benign 15, cc 4295, ddos 6, scan 3 | 224 |
| IoT-Malware-Capture-35-1 | Mirai | malware | 2018-12-21-15-33-59-192.168.1.196.pcap | 24.0 | 46832850 | attack 8, benign 11, cc 4110, ddos 190 | 409 |
| IoT-Malware-Capture-42-1 | Trojan | malware | 2019-01-10-14-34-38-192.168.1.197.pcap | 8.4 | 24485 | benign 1501, cc 2 | 202 |
| IoT-Malware-Capture-44-1 | Mirai | malware | 2019-01-10-21-06-26-192.168.1.199.pcap | 1.9 | 1309350 | cc 327, ddos 16 | 216 |
| IoT-Malware-Capture-48-1 | Mirai | malware | 2019-02-28-19-15-13-192.168.1.200.pcap | 9.8 | 13565553 | scan 1759 | 200 |
| IoT-Malware-Capture-49-1 | Mirai | malware | 2019-02-28-20-50-15-192.168.1.193.pcap | 8.2 | 18111840 | idle 148, scan 1320 | 220 |
| IoT-Malware-Capture-60-1 | Gafgyt | malware | slices/2019-09-20-02-40-32-192.168.1.195.slice-2019-09-20T024100-2019-09-20T025100.pcap | 0.2 | 6629620 | ddos 29 | 29 |
| IoT-Malware-Capture-60-1 | Gafgyt | malware | slices/2019-09-20-02-40-32-192.168.1.195.slice-2019-09-20T043000-2019-09-20T044000.pcap | 0.2 | 6054160 | ddos 29 | 29 |
| IoT-Malware-Capture-60-1 | Gafgyt | malware | slices/2019-09-20-02-40-32-192.168.1.195.slice-2019-09-20T061100-2019-09-20T062100.pcap | 0.2 | 6628238 | ddos 29 | 29 |
| IoT-Malware-Capture-60-1 | Gafgyt | malware | slices/2019-09-20-02-40-32-192.168.1.195.slice-2019-09-20T100000-2019-09-20T103000.pcap | 0.5 | 676 | cc 87 | 87 |
| IoT-Malware-Capture-60-1 | Gafgyt | malware | slices/2019-09-20-02-40-32-192.168.1.195.slice-2019-09-20T140600-2019-09-20T141600.pcap | 0.2 | 5314950 | ddos 29 | 29 |
| IoT-Malware-Capture-60-1 | Gafgyt | malware | slices/2019-09-20-02-40-32-192.168.1.195.slice-2019-09-20T222300-2019-09-20T223000.pcap | 0.1 | 3782166 | cc 2, ddos 18 | 20 |
| IoT-Malware-Capture-7-1 | Mirai | malware | 2018-07-20-17-31-20-192.168.100.108.pcap | 24.0 | 11508430 | benign 25, cc 4107, ddos 3, idle 20, other 164 | 412 |
| IoT-Malware-Capture-8-1 | Hakai | malware | 2018-07-31-15-15-09-192.168.100.113.pcap | 24.0 | 23623 | benign 96, cc 4113, idle 110 | 316 |
| IoT-Malware-Capture-9-1 | Hajime | malware | 2018-07-25-10-53-16-192.168.100.111.pcap | 24.0 | 6437837 | benign 175, idle 653, scan 3490 | 395 |

Label files were checked against the flow counts published on the IoT-23 page:

| Scenario | Label | Published flows | Parsed flows | Match |
|---|---|---:|---:|---|
| IoT-Malware-Capture-1-1 | PartOfAHorizontalPortScan | 539465 | 539465 | yes |
| IoT-Malware-Capture-3-1 | PartOfAHorizontalPortScan | 145597 | 145597 | yes |
| IoT-Malware-Capture-34-1 | DDoS | 14394 | 14394 | yes |
| IoT-Malware-Capture-34-1 | PartOfAHorizontalPortScan | 122 | 122 | yes |
| IoT-Malware-Capture-35-1 | DDoS | 2185302 | 2185302 | yes |
| IoT-Malware-Capture-44-1 | DDoS | 1 | 1 | yes |
| IoT-Malware-Capture-48-1 | PartOfAHorizontalPortScan | 3386119 | 3386119 | yes |
| IoT-Malware-Capture-49-1 | PartOfAHorizontalPortScan | 5404959 | 5404959 | yes |
| IoT-Malware-Capture-60-1 | DDoS | 3578457 | 3578457 | yes |
| IoT-Malware-Capture-7-1 | DDoS | 39584 | 39584 | yes |
| IoT-Malware-Capture-9-1 | PartOfAHorizontalPortScan | 6355745 | 6355745 | yes |

## A. Transfer: the paper's network detector on IoT-23

Training rows: 240 (114 malicious).
Probability given to an all-zero network vector (no traffic): 0.381.

| Measure | Value |
|---|---:|
| DDoS recall | 100.0% |
| Scan recall | 99.9% |
| Attack recall | 100.0% |
| C&C-only recall | 79.2% |
| False alarms on benign devices (mean of 3 devices) | 56.9% |
| Balanced accuracy, DDoS vs benign devices | 71.6% |
| AUC, attack vs benign devices (pooled) | 0.971 |
| AUC, cc vs benign devices (pooled) | 0.767 |
| AUC, ddos vs benign devices (pooled) | 0.944 |
| AUC, scan vs benign devices (pooled) | 0.883 |

| Chunk category | Chunks | Scenarios | Flagged (mean over scenarios) | Flagged (pooled) | Median probability |
|---|---:|---:|---:|---:|---:|
| DDoS (malware capture, DDoS flows overlap the chunk) | 349 | 5 | 100.0% | 349 (100.0%) | 0.924 |
| Scan (horizontal port scan flows, no DDoS) | 1003 | 6 | 99.9% | 1002 (99.9%) | 0.931 |
| Attack (other attack flows) | 8 | 1 | 100.0% | 8 (100.0%) | 0.942 |
| C&C only (C&C, heartbeat or download flows) | 1491 | 9 | 79.2% | 1212 (81.3%) | 0.837 |
| Other malicious label | 164 | 1 | 99.4% | 163 (99.4%) | 0.821 |
| Benign device traffic (Hue, Echo, Somfy) | 1800 | 3 | 56.9% | 1024 (56.9%) | 0.532 |
| Control: infected device, only benign-labeled flows | 566 | 9 | 86.8% | 426 (75.3%) | 0.762 |
| Control: infected device, no flow | 102 | 7 | 14.3% | 20 (19.6%) | 0.381 |
| Control: benign device, no flow | 14 | 1 | 0.0% | 0 (0.0%) | 0.381 |

Per scenario:

| Category | Scenario | Family | Chunks | Flagged |
|---|---|---|---:|---:|
| ddos | IoT-Malware-Capture-34-1 | Mirai | 6 | 6 (100.0%) |
| ddos | IoT-Malware-Capture-35-1 | Mirai | 190 | 190 (100.0%) |
| ddos | IoT-Malware-Capture-44-1 | Mirai | 16 | 16 (100.0%) |
| ddos | IoT-Malware-Capture-60-1 | Gafgyt | 134 | 134 (100.0%) |
| ddos | IoT-Malware-Capture-7-1 | Mirai | 3 | 3 (100.0%) |
| scan | IoT-Malware-Capture-1-1 | Hide and Seek | 200 | 200 (100.0%) |
| scan | IoT-Malware-Capture-3-1 | Muhstik | 200 | 199 (99.5%) |
| scan | IoT-Malware-Capture-34-1 | Mirai | 3 | 3 (100.0%) |
| scan | IoT-Malware-Capture-48-1 | Mirai | 200 | 200 (100.0%) |
| scan | IoT-Malware-Capture-49-1 | Mirai | 200 | 200 (100.0%) |
| scan | IoT-Malware-Capture-9-1 | Hajime | 200 | 200 (100.0%) |
| attack | IoT-Malware-Capture-35-1 | Mirai | 8 | 8 (100.0%) |
| cc | IoT-Malware-Capture-20-1 | Torii | 200 | 200 (100.0%) |
| cc | IoT-Malware-Capture-21-1 | Torii | 200 | 200 (100.0%) |
| cc | IoT-Malware-Capture-34-1 | Mirai | 200 | 115 (57.5%) |
| cc | IoT-Malware-Capture-35-1 | Mirai | 200 | 200 (100.0%) |
| cc | IoT-Malware-Capture-42-1 | Trojan | 2 | 2 (100.0%) |
| cc | IoT-Malware-Capture-44-1 | Mirai | 200 | 86 (43.0%) |
| cc | IoT-Malware-Capture-60-1 | Gafgyt | 89 | 13 (14.6%) |
| cc | IoT-Malware-Capture-7-1 | Mirai | 200 | 196 (98.0%) |
| cc | IoT-Malware-Capture-8-1 | Hakai | 200 | 200 (100.0%) |
| benign_device | Honeypot-Capture-4-1 | Philips Hue | 600 | 237 (39.5%) |
| benign_device | Honeypot-Capture-5-1 | Amazon Echo | 600 | 535 (89.2%) |
| benign_device | Honeypot-Capture-7-1 | Somfy door lock | 600 | 252 (42.0%) |
| infected_quiet | IoT-Malware-Capture-20-1 | Torii | 21 | 21 (100.0%) |
| infected_quiet | IoT-Malware-Capture-21-1 | Torii | 22 | 20 (90.9%) |
| infected_quiet | IoT-Malware-Capture-3-1 | Muhstik | 1 | 1 (100.0%) |
| infected_quiet | IoT-Malware-Capture-34-1 | Mirai | 15 | 12 (80.0%) |
| infected_quiet | IoT-Malware-Capture-35-1 | Mirai | 11 | 11 (100.0%) |
| infected_quiet | IoT-Malware-Capture-42-1 | Trojan | 200 | 107 (53.5%) |
| infected_quiet | IoT-Malware-Capture-7-1 | Mirai | 25 | 20 (80.0%) |
| infected_quiet | IoT-Malware-Capture-8-1 | Hakai | 96 | 91 (94.8%) |
| infected_quiet | IoT-Malware-Capture-9-1 | Hajime | 175 | 143 (81.7%) |

## B. Within IoT-23: same features, retrained, leave-one-scenario-out

| Measure | Value |
|---|---:|
| DDoS recall | 98.8% |
| Scan recall | 99.8% |
| Attack recall | 100.0% |
| C&C-only recall | 81.9% |
| False alarms on benign devices (mean of 3 devices) | 37.3% |
| Balanced accuracy, DDoS vs benign devices | 80.7% |
| AUC, attack vs benign devices (pooled) | 1.000 |
| AUC, cc vs benign devices (pooled) | 0.872 |
| AUC, ddos vs benign devices (pooled) | 0.964 |
| AUC, scan vs benign devices (pooled) | 0.990 |

| Chunk category | Chunks | Scenarios | Flagged (mean over scenarios) | Flagged (pooled) | Median probability |
|---|---:|---:|---:|---:|---:|
| DDoS (malware capture, DDoS flows overlap the chunk) | 349 | 5 | 98.8% | 348 (99.7%) | 0.994 |
| Scan (horizontal port scan flows, no DDoS) | 1003 | 6 | 99.8% | 1000 (99.7%) | 0.998 |
| Attack (other attack flows) | 8 | 1 | 100.0% | 8 (100.0%) | 1.000 |
| C&C only (C&C, heartbeat or download flows) | 1491 | 9 | 81.9% | 1227 (82.3%) | 0.996 |
| Other malicious label | 164 | 1 | 98.8% | 162 (98.8%) | 0.910 |
| Benign device traffic (Hue, Echo, Somfy) | 1800 | 3 | 37.3% | 672 (37.3%) | 0.279 |
| Control: infected device, only benign-labeled flows | 566 | 9 | 78.6% | 333 (58.8%) | 0.850 |
| Control: infected device, no flow | 102 | 7 | 14.3% | 20 (19.6%) | 0.450 |
| Control: benign device, no flow | 14 | 1 | 0.0% | 0 (0.0%) | 0.334 |

Per scenario:

| Category | Scenario | Family | Chunks | Flagged |
|---|---|---|---:|---:|
| ddos | IoT-Malware-Capture-34-1 | Mirai | 6 | 6 (100.0%) |
| ddos | IoT-Malware-Capture-35-1 | Mirai | 190 | 190 (100.0%) |
| ddos | IoT-Malware-Capture-44-1 | Mirai | 16 | 15 (93.8%) |
| ddos | IoT-Malware-Capture-60-1 | Gafgyt | 134 | 134 (100.0%) |
| ddos | IoT-Malware-Capture-7-1 | Mirai | 3 | 3 (100.0%) |
| scan | IoT-Malware-Capture-1-1 | Hide and Seek | 200 | 200 (100.0%) |
| scan | IoT-Malware-Capture-3-1 | Muhstik | 200 | 197 (98.5%) |
| scan | IoT-Malware-Capture-34-1 | Mirai | 3 | 3 (100.0%) |
| scan | IoT-Malware-Capture-48-1 | Mirai | 200 | 200 (100.0%) |
| scan | IoT-Malware-Capture-49-1 | Mirai | 200 | 200 (100.0%) |
| scan | IoT-Malware-Capture-9-1 | Hajime | 200 | 200 (100.0%) |
| attack | IoT-Malware-Capture-35-1 | Mirai | 8 | 8 (100.0%) |
| cc | IoT-Malware-Capture-20-1 | Torii | 200 | 198 (99.0%) |
| cc | IoT-Malware-Capture-21-1 | Torii | 200 | 198 (99.0%) |
| cc | IoT-Malware-Capture-34-1 | Mirai | 200 | 99 (49.5%) |
| cc | IoT-Malware-Capture-35-1 | Mirai | 200 | 200 (100.0%) |
| cc | IoT-Malware-Capture-42-1 | Trojan | 2 | 2 (100.0%) |
| cc | IoT-Malware-Capture-44-1 | Mirai | 200 | 118 (59.0%) |
| cc | IoT-Malware-Capture-60-1 | Gafgyt | 89 | 40 (44.9%) |
| cc | IoT-Malware-Capture-7-1 | Mirai | 200 | 196 (98.0%) |
| cc | IoT-Malware-Capture-8-1 | Hakai | 200 | 176 (88.0%) |
| benign_device | Honeypot-Capture-4-1 | Philips Hue | 600 | 362 (60.3%) |
| benign_device | Honeypot-Capture-5-1 | Amazon Echo | 600 | 310 (51.7%) |
| benign_device | Honeypot-Capture-7-1 | Somfy door lock | 600 | 0 (0.0%) |
| infected_quiet | IoT-Malware-Capture-20-1 | Torii | 21 | 19 (90.5%) |
| infected_quiet | IoT-Malware-Capture-21-1 | Torii | 22 | 20 (90.9%) |
| infected_quiet | IoT-Malware-Capture-3-1 | Muhstik | 1 | 1 (100.0%) |
| infected_quiet | IoT-Malware-Capture-34-1 | Mirai | 15 | 11 (73.3%) |
| infected_quiet | IoT-Malware-Capture-35-1 | Mirai | 11 | 11 (100.0%) |
| infected_quiet | IoT-Malware-Capture-42-1 | Trojan | 200 | 122 (61.0%) |
| infected_quiet | IoT-Malware-Capture-7-1 | Mirai | 25 | 18 (72.0%) |
| infected_quiet | IoT-Malware-Capture-8-1 | Hakai | 96 | 95 (99.0%) |
| infected_quiet | IoT-Malware-Capture-9-1 | Hajime | 175 | 36 (20.6%) |

## Feature medians

IoT-23 chunk groups and the categories of the training dataset (`dataset:`):

| Group | n | pkts_per_sec__mean | flow_count_seen__max | syn__sum | ack__sum | flows_with_ba__max | avg_pkt_size__mean | pkts_total__active_windows |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| iot23:attack | 8 | 190 | 720 | 3.77e+03 | 14.5 | 2 | 69.5 | 37.5 |
| iot23:benign_device | 1800 | 0.4 | 1 | 0 | 3 | 1 | 19.2 | 3 |
| iot23:benign_idle | 14 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| iot23:cc | 1491 | 0.4 | 1 | 0 | 4 | 1 | 7.67 | 4 |
| iot23:ddos | 349 | 4.41e+03 | 686 | 3.22e+03 | 4 | 1 | 70.3 | 40 |
| iot23:infected_idle | 102 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| iot23:infected_quiet | 566 | 0.15 | 1 | 0 | 0 | 1 | 4.5 | 2 |
| iot23:other_malicious | 164 | 75.7 | 321 | 1.51e+03 | 1 | 1 | 18 | 12 |
| iot23:scan | 1003 | 96.2 | 193 | 1.92e+03 | 3 | 1 | 55.5 | 33 |
| dataset:benign | 105 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| dataset:malware | 99 | 0.4 | 1 | 0 | 0 | 0 | 4.6 | 2 |
| dataset:network_attack | 15 | 1.99e+03 | 1.02e+03 | 3.21e+03 | 2.9e+03 | 150 | 14.8 | 8 |
| dataset:network_benign | 18 | 550 | 166 | 800 | 7.15e+03 | 166 | 54.8 | 15 |
| dataset:null | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Checks

- **Feature equivalence.** The single pass over each capture equals `switch_model.window_features()` on
  92 sampled chunks from 23 capture files (20 DDoS, 11 scan, 18 C&C, 42 benign, 1 other), with no
  difference in any of the 145 columns. The four files above 1 GB (35-1, 44-1, 48-1, 49-1) go through the
  same code but were not re-read by the reference, which reads the whole file for every chunk.
- **Labels.** All 11 published flow counts match the parsed label files exactly.
- **One device per capture.** In the six captures checked, the device's address is in 100% of TCP/UDP packets.
- **Label gap.** The label log of 49-1 ends before the capture does. Its last 148 chunks hold about 12,000
  SYNs each, so the scan goes on, but no labeled flow overlaps them; they fall into the control "infected
  device, no flow". All 20 flagged chunks of that control come from this gap. No other capture has an
  unlabeled chunk with 100 frames or more.
- **Provenance.** The SHA-256 in the published `.capinfos` of the Hue capture (4-1) differs from that of the
  published `.pcap.xz` once unpacked, although packet count and size agree. protocol.json records the
  hashes of the files actually used.

## Reading

1. **Real bot attacks are caught by the unchanged detector.** Trained only on the lab dataset, whose
   attack examples are 15 tool-generated floods, it flags all 349 DDoS chunks (Mirai in four captures,
   Gafgyt) and 1,002 of 1,003 scan chunks (Mirai, Hajime, Muhstik, Hide and Seek). Gafgyt's floods differ
   from the lab ones: 29- and 93-byte UDP packets at 3,000 to 11,000 packets/s in single-flow floods, and
   one flood of 3.6 million single-packet TCP flows.
2. **Its false-alarm rate does not carry over.** It flags 39.5% (Hue), 42.0% (Somfy) and 89.2% (Echo) of
   benign-device chunks. In these features, low-rate device chatter looks like the dataset's malware
   (median 0.4 packets/s and one flow, the same as the dataset's mostly network-quiet malware, whose few C2
   lookups and connection attempts are its only traffic). The dataset's benign rows are either silent
   command-line programs or heavy transfers; none has low-rate background traffic.
3. **The C&C-only figure is not evidence of C&C detection.** Chunks of infected devices whose flows are
   all labeled benign are flagged as often (86.8%) as C&C-only chunks (79.2%). The detector reacts to
   low-rate traffic in general.
4. **Retraining on IoT-23 does not fix the false alarms.** DDoS and scan recall stay near 100%, but 37% of
   benign-device chunks are still flagged (Hue 60%, Echo 52%, Somfy 0%), and infected-but-quiet chunks 79%.
   With three benign devices, each fold learns from two, and the model separates the Raspberry Pi's
   chatter from the consumer devices rather than attacks from benign traffic.
5. **Ranking is better than the fixed threshold.** AUC against benign devices is 0.944 for DDoS and
   0.883 for scans (A). No threshold was tuned on these data.

## What this means for the paper

- It supports the scoped network claim on real malware traffic: the switch's flow features and the paper's
  trained detector catch volumetric floods and scans from real IoT bots of several families, beyond the
  sandbox's single live flood family (Kaiten).
- It shows a limitation the lab data could not: on always-on devices with low-rate background traffic,
  the network detector raises many false alarms, because no benign training row has such traffic.
  Benign background traffic (heartbeats, keepalives, NTP and DNS) belongs in the benign training set, or
  the network score should only be trusted for high-volume patterns.
- It tests the network half only. IoT-23 has no host data, so the fusion is not tested.

## Limits

- Chunks are cut from long captures. A flow already open when a chunk starts takes its direction from its
  first packet in the chunk; in the lab, every flow started inside the observation.
- Chunks of one flood or scan are strongly correlated: the 349 DDoS chunks come from 2 families and 5
  captures. Gafgyt is represented by six time slices of one capture, chosen by flood type from the labels.
- Not downloaded: Kenjiro's DDoS capture (17-1) and the largest scan captures (33-1, 39-1, 43-1, 52-1).
- The benign side is three consumer IoT devices.
- Different setting: real Internet and C2, Raspberry Pi (ARM) hosts, traffic from 2018 and 2019.

## Reproduce

From `iot23-external/` (Python 3.10 with numpy and scikit-learn in the user site):

    python3 -I fetch_iot23.py DATA                     # pcaps, label logs, READMEs; no binaries
    xz -dk DATA/CTU-Honeypot-Capture-4-1/*.pcap.xz
    python3 -I slice_iot23.py URL-of-60-1-pcap DATA/CTU-IoT-Malware-Capture-60-1/slices \
        2019-09-20T02:41:00 2019-09-20T02:51:00 2019-09-20T04:30:00 2019-09-20T04:40:00 \
        2019-09-20T06:11:00 2019-09-20T06:21:00 2019-09-20T10:00:00 2019-09-20T10:30:00 \
        2019-09-20T14:06:00 2019-09-20T14:16:00 2019-09-20T22:23:00 2019-09-20T22:30:00
    python3 -I prepare_iot23.py DATA OUT --jobs 8
    python3 -I prepare_iot23.py DATA OUT --self-check --jobs 12
    python3 -I evaluate_iot23.py OUT
    python3 -I report_iot23.py OUT OUT/evaluation-*
