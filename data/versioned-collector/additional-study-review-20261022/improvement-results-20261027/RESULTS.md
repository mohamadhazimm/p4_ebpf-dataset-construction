# Improvement results — offline, no VM (2026-10-27)

Read-only / offline work on the scoped hybrid study. No VM operation, no sample
execution, no model promotion, no dataset merge. Numbers below are reproducible
from saved artifacts.

## 1. Bot-IoT reproduction — second independent network dataset

Dataset: `Bot-IOT.zip` (UNSW-NB 2018 IoT Botnet, 5% full-feature set), streamed
from the zip without extraction. Features: the same payload-free, identity-free
per-flow stats used for CIC-DDoS2019 (dur, mean, stddev, sum, min, max, pkts,
bytes, spkts, dpkts, sbytes, dbytes, rate, srate, drate). Explicitly EXCLUDED:
addresses, ports, timestamps, seq/pkSeqID, proto/flgs strings, and all IP-keyed
aggregate features (TnBP*, TnP_*, AR_*, N_IN_Conn_*). RF200, seed 42, 70/30
stratified, one-vs-Normal per category, balanced to the min class.

Full-set class counts: DDoS 1,926,624 · DoS 1,650,260 · Reconnaissance 91,082 ·
Normal 477 · Theft 79.

| Normal vs | Balanced acc | Test acc | n per class | top feature |
|---|---|---|---|---|
| DoS | 1.0000 | 1.0000 | 477 | sbytes |
| DDoS | 0.9965 | 0.9965 | 477 | sbytes |
| Reconnaissance | 0.9409 | 0.9408 | 477 | sbytes |
| Theft | 0.8958 | 0.8958 | 79 | rate |
| All attacks vs Normal | 0.9443 | 0.9443 | 477 | — |

Reading: a second, independent public dataset confirms the payload-free flow
features separate attack from normal traffic, and unlike CIC it includes
non-volumetric classes (Reconnaissance, Theft), widening the network-sensor
claim beyond pure floods. Caveats: Bot-IoT Normal is tiny (477 flows in the 5%
set) so pairs balance to 477/class (79 for Theft); in-distribution, same-capture,
like CIC. Raw output: `botiot_results.json`.

## 2. Combined-surface paired statistics (expanded 126-benign pool, 10 fold-seeds)

Source: `combined-surface-expanded/20261027T165348Z/expanded_cv.json`.

| Detector | BA mean±sd | gen-malware recall | flood recall | specificity |
|---|---|---|---|---|
| Host | 0.784 ± 0.021 | 0.715 | 0.940 | 0.824 |
| Network (P4) | 0.756 ± 0.015 | 0.520 | 0.987 | 0.931 |
| Hybrid | 0.823 ± 0.014 | 0.739 | 0.993 | 0.874 |

Paired hybrid − host BA: mean **+0.039**, sd 0.024, approx 95% CI
**[+0.024, +0.054]**, hybrid wins **9/10** fold-seeds. The CI excludes zero, so
the hybrid margin is a real effect, not seed noise — report it this way to make
"hybrid is strongest" rigorous.

### Framing correction (important for the paper)
In the TRAINED combined-surface random forest, the host model ALSO catches
floods (flood recall 0.94) because floods are host-loud (~1.9e7 syscalls). So
the hybrid's edge is NOT "only P4 sees floods" in this classifier — it comes
from modestly better general-malware recall (+0.024 paired) AND better
specificity (0.874 vs 0.824). The "two sensors fail on opposite attack classes,
only fusion covers both" statement is true for the single-threshold host-activity
flood experiment, but overstated for the trained combined RF. Honest combined-
surface sentence: "fusion adds +0.04 BA (95% CI [+0.02, +0.05], 9/10 seeds) by
improving both general-malware recall and benign specificity."

## Status of follow-on tasks
- Cohort expansion (task 3): offline candidate family-held-out selection being
  frozen; VM collection needs explicit per-phase approval.
- Botnet-shaped benign (task 4): sourcing/build design; benign collection needs
  approval.
- Socket-level flow-to-process attribution (task 5): collector design; the eBPF
  side already records connect() remote IPv4:port per PID, so a flow can be
  joined to a process by 5-tuple instead of by time window.
