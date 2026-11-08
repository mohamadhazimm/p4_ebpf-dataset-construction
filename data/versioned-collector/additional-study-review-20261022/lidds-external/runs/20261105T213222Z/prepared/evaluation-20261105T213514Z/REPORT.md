# LID-DS 2021 check of the host, network and hybrid detectors

From `evaluation-20261105T213514Z` (protocol SHA-256 `cc4f9ec4f5c4db461463320be2c846b207198e67d682f182c269499b1c05388c`). Offline; no VM, nothing executed.

## Data

LID-DS 2021 (Leipzig University) records real exploits against services in Docker containers, with
benign users whose timing comes from real web-server logs. Each recording has the victim container's
system calls and packet capture. Five of its 15 scenarios were used:

| Scenario | Recordings | Attack windows | Normal windows | Skipped (shorter than 10 s) |
|---|---:|---:|---:|---:|
| Password brute force (CWE-307) | 1177 | 137 | 1038 | 2 |
| MySQL login bypass (CVE-2012-2122) | 1152 | 115 | 1032 | 5 |
| Heartbleed (CVE-2014-0160) | 1148 | 118 | 1028 | 2 |
| SQL injection (CWE-89) | 1150 | 120 | 1030 | 0 |
| PHP upload to web shell (CWE-434) | 1147 | 115 | 1029 | 3 |

One 10-s observation (20 windows of 0.5 s) per recording, with the paper's 90 host and 145 network
columns: the host features from the call-entry events of the victim's processes (`features/host_model.py`),
the network features from the frames of the victim's Ethernet interface through `features/switch_model.py`
(loopback frames dropped: a switch never sees them). Attack windows start 2 s before the logged attack
time; normal windows follow the same rule around a pseudo attack time drawn from the same scenario's
attack offsets. Controls: a second window of every normal recording placed near its end the way attack
windows are; never trained on.

## E1. Unseen attack type: leave one scenario out (primary)

Mean over the five held-out scenarios:

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.3% | 0.9% | 0.2% | 0.0% | 0.705 |
| network-only | 73.8% | 47.9% | 0.3% | 0.0% | 0.857 |
| hybrid | 71.7% | 64.4% | 20.9% | 19.8% | 0.798 |
| concatenated | 72.1% | 44.6% | 0.4% | 0.0% | 0.840 |
| activity-only | 76.1% | 52.4% | 0.2% | 0.1% | 0.810 |
| position-only | 82.5% | 68.5% | 3.4% | 59.0% | 0.894 |

**Held out: Password brute force (CWE-307)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.0% | 0.0% | 0.0% | 0.1% | 0.646 |
| network-only | 97.8% | 95.6% | 0.0% | 0.0% | 1.000 |
| hybrid | 98.2% | 96.4% | 0.0% | 0.5% | 0.999 |
| concatenated | 96.7% | 93.4% | 0.0% | 0.0% | 0.999 |
| activity-only | 96.5% | 93.4% | 0.5% | 0.3% | 0.989 |
| position-only | 96.9% | 94.9% | 1.1% | 91.8% | 0.997 |
**Held out: MySQL login bypass (CVE-2012-2122)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.677 |
| network-only | 82.6% | 65.2% | 0.0% | 0.0% | 0.863 |
| hybrid | 51.2% | 99.1% | 96.8% | 97.0% | 0.892 |
| concatenated | 82.6% | 65.2% | 0.0% | 0.0% | 0.743 |
| activity-only | 82.6% | 65.2% | 0.0% | 0.0% | 0.858 |
| position-only | 76.2% | 54.8% | 2.3% | 30.9% | 0.803 |
**Held out: Heartbleed (CVE-2014-0160)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.623 |
| network-only | 50.0% | 0.0% | 0.0% | 0.0% | 0.778 |
| hybrid | 59.0% | 18.6% | 0.6% | 1.2% | 0.674 |
| concatenated | 50.0% | 0.0% | 0.0% | 0.0% | 0.829 |
| activity-only | 50.0% | 0.0% | 0.1% | 0.1% | 0.575 |
| position-only | 90.9% | 94.1% | 12.3% | 83.6% | 0.975 |
**Held out: SQL injection (CWE-89)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 50.4% | 0.8% | 0.0% | 0.0% | 0.887 |
| network-only | 85.8% | 71.7% | 0.0% | 0.0% | 1.000 |
| hybrid | 99.0% | 100.0% | 2.0% | 0.4% | 1.000 |
| concatenated | 78.8% | 57.5% | 0.0% | 0.0% | 1.000 |
| activity-only | 99.5% | 99.2% | 0.2% | 0.3% | 1.000 |
| position-only | 54.1% | 9.2% | 0.9% | 14.0% | 0.699 |
**Held out: PHP upload to web shell (CWE-434)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 51.2% | 3.5% | 1.2% | 0.0% | 0.691 |
| network-only | 52.7% | 7.0% | 1.6% | 0.0% | 0.643 |
| hybrid | 51.4% | 7.8% | 5.1% | 0.0% | 0.424 |
| concatenated | 52.6% | 7.0% | 1.8% | 0.0% | 0.632 |
| activity-only | 52.0% | 4.3% | 0.4% | 0.0% | 0.627 |
| position-only | 94.4% | 89.6% | 0.7% | 74.9% | 0.998 |

## E2. Seen attack types: 5-fold cross-validation over the pooled scenarios

Pooled:

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 90.0% | 80.2% | 0.1% | 0.0% | 0.996 |
| network-only | 92.1% | 84.1% | 0.0% | 0.0% | 0.996 |
| hybrid | 97.8% | 96.2% | 0.6% | 0.2% | 0.999 |
| concatenated | 94.0% | 88.1% | 0.0% | 0.0% | 0.999 |
| activity-only | 80.3% | 61.5% | 0.8% | 0.6% | 0.880 |
| position-only | 93.9% | 88.9% | 1.0% | 44.8% | 0.996 |

**Password brute force (CWE-307)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 95.3% | 90.5% | 0.0% | 0.1% | 1.000 |
| network-only | 99.6% | 99.3% | 0.0% | 0.0% | 1.000 |
| hybrid | 99.5% | 99.3% | 0.2% | 0.2% | 1.000 |
| concatenated | 99.3% | 98.5% | 0.0% | 0.0% | 1.000 |
| activity-only | 96.6% | 93.4% | 0.2% | 0.3% | 0.993 |
| position-only | 97.5% | 96.4% | 1.3% | 40.1% | 0.998 |
**MySQL login bypass (CVE-2012-2122)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 98.6% | 97.4% | 0.1% | 0.0% | 1.000 |
| network-only | 99.1% | 98.3% | 0.0% | 0.0% | 1.000 |
| hybrid | 100.0% | 100.0% | 0.1% | 0.0% | 1.000 |
| concatenated | 99.1% | 98.3% | 0.0% | 0.0% | 1.000 |
| activity-only | 82.5% | 65.2% | 0.3% | 0.4% | 0.818 |
| position-only | 93.4% | 88.7% | 1.9% | 37.0% | 0.990 |
**Heartbleed (CVE-2014-0160)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 80.9% | 61.9% | 0.1% | 0.1% | 0.988 |
| network-only | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| hybrid | 99.7% | 100.0% | 0.7% | 0.4% | 1.000 |
| concatenated | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| activity-only | 59.1% | 20.3% | 2.2% | 2.1% | 0.718 |
| position-only | 97.2% | 94.9% | 0.6% | 32.9% | 0.999 |
**SQL injection (CWE-89)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| network-only | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| hybrid | 100.0% | 100.0% | 0.1% | 0.0% | 1.000 |
| concatenated | 100.0% | 100.0% | 0.0% | 0.0% | 1.000 |
| activity-only | 99.9% | 100.0% | 0.2% | 0.0% | 1.000 |
| position-only | 83.3% | 67.5% | 0.9% | 75.5% | 0.991 |
**PHP upload to web shell (CWE-434)**

| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |
|---|---:|---:|---:|---:|---:|
| host-only | 74.2% | 48.7% | 0.3% | 0.0% | 0.975 |
| network-only | 59.6% | 19.1% | 0.0% | 0.0% | 0.921 |
| hybrid | 89.4% | 80.9% | 2.1% | 0.4% | 0.980 |
| concatenated | 70.4% | 40.9% | 0.0% | 0.0% | 0.986 |
| activity-only | 60.2% | 21.7% | 1.3% | 0.1% | 0.697 |
| position-only | 98.0% | 96.5% | 0.5% | 38.6% | 0.999 |

## Checks

- Packet and byte totals of 10 sampled windows (one attack and one normal per scenario) recomputed with
  tshark from the original cooked captures: all 10 equal to the extracted rows.
- Host: the summed call count of every window equals the number of call-entry events in it; no unknown
  event names (the trace's `pread`/`pwrite`/`sigreturn` mapped to `pread64`/`pwrite64`/`rt_sigreturn`;
  `procexit` and `signaldeliver` are not system calls and were dropped).
- 12 of 5,774 recordings are shorter than the 10-s window and were skipped (5,762 kept; corrected
  2026-11-05 from "22 of 5,762", a miscount in the first version of this report).
- Position: a forest given only the window's position (time since the recording started, time left
  until it ends) scores high, because attack windows are clamped near the end of their short recordings.
  The content models do not use this: they flag 0.0-0.6% of the end-control windows, the same as normal
  windows, while the position-only forest flags 45-59% of them.

## Reading

1. **Seen attack types (E2): fusion helps, most where one sensor is weak.** Pooled balanced accuracy:
   hybrid 97.8%, network 92.1%, host 90.0%. On the PHP upload that becomes a web shell, host 74.2% and
   network 59.6%, hybrid 89.4% (attack recall 80.9% against 48.7% and 19.1%). On Heartbleed, the network
   carries it (100% against host 80.9%) and the hybrid keeps 99.7%. This is the complementary pattern the
   paper argues for, shown on real exploits with host and network data from the same runs, recorded by
   others.
2. **Unseen attack type and service (E1): little transfers.** Host-only flags almost nothing on a held-out
   service (recall 0.9% on average; AUC 0.62-0.89 shows some ranking, but the threshold no longer fits):
   system-call profiles are specific to each service. Network-only transfers for the volume-heavy attacks
   (brute force 97.8%, MySQL login bypass 82.6%, SQL injection 85.8%) but not for Heartbleed or the PHP web
   shell (50% and 52.7%). Activity volume alone does as well on average (76.1% against 73.8%), so what
   transfers across services is mostly "the attack sends more".
3. **The stacked hybrid is unstable under service shift.** It reaches 99.0% on held-out SQL injection but
   collapses on held-out MySQL (99.1% recall with 96.8% false alarms): the stacker's weights, fitted on four
   other services, do not fit a new one.

## Limits

- E2 trains and tests on the same five services and exploits (known attack types, like the paper's
  family-split setting); its high values are expected and the gain of fusion over each sensor is the
  meaningful part.
- Five of 15 scenarios; one exploit per scenario. 10-s observations instead of the paper's 20 s, so the
  paper's trained models are not applied here (their column sums assume 40 windows); each detector is
  retrained on LID-DS.
- The victim is a long-running server, not a launched sample; host features cover all processes of the
  victim container.
