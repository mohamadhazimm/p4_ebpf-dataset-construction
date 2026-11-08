# LID-DS 2021, Test 1 (seen attack types) over ten fold assignments

Run of `repeat_e2_lidds.py` (SHA `b3cc1956…`) on `../evaluation-20261106T011514Z`, 2026-11-06,
offline. It ran at lowest priority on 4 of 12 cores while another session used the VM, about 5
minutes per assignment.
- Protocol `protocol.json` (`a9825a70…`), written before fitting.
- Results `results.json` (`e4b8478b…`) and `per_seed.jsonl`; out-of-fold scores `oof_seed*.npz`.

Same rows, models, inner folds and threshold as Test 1 (E2) of the evaluation. Only the outer fold seed
changes: 42 and 0 to 8, the seeds of the thesis's Table V repeat. Split 42 reproduces the evaluation:
identical decisions at the threshold, and probabilities within 1.1e-16, because the forests sum tree
votes in thread order.

| Detector | Balanced accuracy, mean ± SD (min–max) | AUC |
|---|---:|---:|
| Host-only | 85.8 ± 0.2% (85.6–86.0) | 0.982 |
| Network-only | 88.5 ± 0.1% (88.4–88.7) | 0.991 |
| Hybrid (stacked) | 96.0 ± 0.1% (95.8–96.3) | 0.995 |
| Concatenated | 91.2 ± 0.2% (90.9–91.4) | 0.996 |
| Activity-only | 70.5 ± 0.2% (70.0–70.7) | 0.811 |
| Position-only | 83.9 ± 0.2% (83.5–84.3) | 0.970 |

Gain in attack recall over the better single sensor at the same false-alarm rate on normal windows.
The better sensor is the network in every assignment. Values are points, mean ± SD (min–max), and the
gain is positive in 10 of 10 assignments at every rate:

| False alarms | Hybrid | Concatenated |
|---:|---:|---:|
| 0.1% | +5.7 ± 0.7 (4.6–7.1) | +7.5 ± 1.0 (6.2–8.9) |
| 1% | +5.6 ± 0.4 (5.1–6.2) | +6.2 ± 0.4 (5.6–6.9) |
| 2% | +4.4 ± 0.3 (4.0–4.8) | +5.1 ± 0.4 (4.5–5.7) |
| 5% | +2.4 ± 0.2 (2.0–3.0) | +3.6 ± 0.3 (3.3–4.1) |

The hybrid is at least as good as the better single sensor in 12 to 14 of the 15 scenarios (mean 13.3).

Thesis write-up: `data/lab/lidds2021.md` and `data/lab/lidds2021.json` in the thesis repository.
