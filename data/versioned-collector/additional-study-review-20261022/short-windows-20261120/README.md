# Shorter windows: 0.25 s and 0.1 s instead of 0.5 s (2026-11-20)

The switch on PC1 is being run with 0.1-s and 0.25-s windows. This folder rebuilds the two datasets at those
window lengths from the raw data and scores them. Offline: no VM, switch or sample was run.

The observation stays the same 20 s (or 80 s in the session dataset), from the same anchors:
0.25 s × 80 and 0.1 s × 200 windows end where 0.5 s × 40 end. The feature definitions are the release's
(`features/switch_model.py`, `host_model.py`, `summary.py`), unchanged. The active-flow TTL stays 3 windows at
every window length (0.3 s at 0.1 s, 0.75 s at 0.25 s), as in the exact build's data plane
(`p4_ebpf/thesis-hybrid-ebpf-p4/python/exact_model.py`, `TTL = 3`). Rates are over the nominal window.

## What can be rebuilt

| | paper dataset (240 runs) | session dataset (435 rows) |
|---|---|---|
| network | yes: every packet's time is in the run's capture | yes: every packet's time is in the Sink capture |
| host | yes: every system call's time is in `syscall_events.csv` | **no**: the in-kernel monitor kept one row of statistics per process and 0.5-s window, not the calls |

So the session dataset is scored with the network columns at 0.25 s or 0.1 s and the host columns at 0.5 s, both
over the same 20-s (or 80-s) span from the injection. Shorter host windows for the sessions would need the
sessions collected again with the monitor at the shorter window.

For the paper dataset there are three variants at each shorter window:

- **matched**: host and network at the shorter window;
- **mixed**: host at 0.5 s (the published columns), network at the shorter window, the same 20 s. This is the
  design the session dataset allows, so it is also scored on the paper rows for comparison;
- **prologue-free**: as matched, without the launch prologue on the host side (178 calls per run), as in
  `../launcher-ablation-05s/`.

## Files

| file | what |
|---|---|
| `build_short.py` | the 240 rows at 0.5, 0.25 and 0.1 s from the raw runs, with gates |
| `build_session_short.py` | the session dataset's network columns at 0.5, 0.25 and 0.1 s, with gates |
| `score_short.py` | both datasets scored with the four detectors |
| `run-20261120/features_<ms>ms_<host>.csv` | the 240 rows in `dataset/features.csv`'s layout (metadata unchanged) |
| `run-20261120/windows_<ms>ms.npz` | per-window arrays: N (240, n, 29), H and Hpf (240, n, 18) |
| `run-20261120/dataset_windows_<ms>ms_<host>.csv.gz` | per-window tables in `p4_ebpf/live_test/streaming/dataset_windows.csv.gz`'s format |
| `run-20261120/session/session_<ms>ms_<span>.csv` | the session rows in `build_base.py`'s layout (host = the 0.5-s columns) |
| `run-20261120/session/session_windows_<ms>ms.npz` | each session row's network windows over its 80-s span |
| `run-20261120/build.json`, `session/session_build.json` | gates, checks, hashes |
| `run-20261120/scores.json` | all scores |

Reproduce from this folder with `/usr/bin/python3` (scikit-learn 1.7; Table V and the session CV need < 1.8):

```sh
/usr/bin/python3 build_short.py run-20261120 --jobs 12
/usr/bin/python3 build_session_short.py run-20261120/session --jobs 12
/usr/bin/python3 score_short.py run-20261120
```

## Gates (all passed)

Paper rows, at 0.5 s, for all 240 runs:

- every saved system call's window, recomputed from its timestamp on the runner's grid
  (`(timestamp_ns - sample_started_monotonic_ns) // window_ns`), equals the saved `window_id` (0 mismatches);
  every call lies in the 20 s; `observation_ended - sample_started` is exactly 20 s in every run;
- the rebuilt windows equal each run's `telemetry.csv` in every window (network exactly, host to 1.1e-15);
- the summaries equal the published rows (network exactly, host to 9.3e-16); the prologue-free rows equal
  `../launcher-ablation-05s/`'s to 1.8e-15; the prologue is 178 calls in all 240.

Session rows, at 0.5 s, for all 435 rows: the rebuilt network windows equal each session's `windows.json` in
all 360 windows; the summaries equal `build_base.py`'s matrices exactly and the base's CSVs to their 10
significant digits.

Both datasets, at 0.25 s and 0.1 s: every 0.5-s window is exactly the sum of its 2 or 5 shorter windows for the
additive features (packets and bytes in each direction, SYN, ACK, RST, and host calls).

Scores, at 0.5 s: the paper rows reproduce the cached Table V out-of-fold probabilities of all four detectors
exactly and Table IV's published confusions; the session rows reproduce `base/20261117c/base.json` exactly.

## What the shorter windows change in the data

Share of windows with traffic (network) or calls (host), and the most active flows in one window:

| window | malware net / host | CLI benign host | network benign net | attacks net | most flows in a window (attacks) |
|---|---|---|---|---|---|
| 0.5 s | 14.7% / 20.4% | 4.2% | 40.0% | 30.8% | 98,104 |
| 0.25 s | 8.4% / 13.1% | 3.1% | 39.2% | 29.8% | 50,272 |
| 0.1 s | 4.4% / 8.2% | 2.1% | 35.5% | 29.0% | 22,551 |

The same activity is spread over more windows, most of them empty. With the TTL fixed at 3 windows, a flow
stays active for a shorter time, so fewer flows are active at once.

## Results

All tables: `run-20261120/scores.txt` (from `summarize_scores.py`; no refit). The variants share the fold
assignments (the folds depend only on the labels and groups), so changes against 0.5 s are paired per assignment.

### Paper dataset, Table V protocol (grouped CV, 10 fold assignments): balanced accuracy

| variant | host | network | concatenated | stacked |
|---|---|---|---|---|
| 0.5 s (published) | 0.784 ± 0.022 | 0.756 ± 0.016 | 0.812 ± 0.021 | 0.823 ± 0.015 |
| 0.25 s matched | 0.768 ± 0.016 | 0.758 ± 0.016 | 0.811 ± 0.021 | 0.818 ± 0.020 |
| 0.25 s mixed | 0.784 ± 0.022 | 0.758 ± 0.016 | 0.813 ± 0.021 | 0.826 ± 0.015 |
| 0.1 s matched | 0.774 ± 0.022 | 0.766 ± 0.017 | 0.812 ± 0.022 | 0.822 ± 0.019 |
| 0.1 s mixed | 0.784 ± 0.022 | 0.766 ± 0.017 | 0.821 ± 0.023 | 0.825 ± 0.018 |
| 0.5 s prologue-free | 0.832 ± 0.023 | 0.756 ± 0.016 | 0.836 ± 0.025 | 0.866 ± 0.026 |
| 0.25 s prologue-free | 0.818 ± 0.022 | 0.758 ± 0.016 | 0.838 ± 0.026 | 0.851 ± 0.030 |
| 0.1 s prologue-free | 0.829 ± 0.023 | 0.766 ± 0.017 | 0.848 ± 0.026 | 0.866 ± 0.026 |

Change against 0.5 s, mean over the assignments (assignments higher, of 10):

| variant | host | network | concatenated | stacked |
|---|---|---|---|---|
| 0.25 s matched | −0.017 (1) | +0.001 (5) | −0.001 (4) | −0.005 (2) |
| 0.25 s mixed | 0 | +0.001 (5) | +0.001 (3) | +0.003 (5) |
| 0.1 s matched | −0.010 (2) | +0.010 (8) | −0.000 (4) | −0.002 (4) |
| 0.1 s mixed | 0 | +0.010 (8) | +0.008 (8) | +0.002 (5) |

- Both hybrids stay within 0.01 of their 0.5-s scores, and both stay above host in every variant:
  concatenated minus host +0.028 (10 of 10) at 0.5 s, +0.038 (10) at 0.1 s matched, +0.036 (10) at 0.1 s mixed;
  stacked minus host +0.039 (9), +0.048 (9), +0.041 (10).
- Host at a shorter window is slightly lower: −0.017 at 0.25 s (higher in 1 of 10 assignments), −0.010 at 0.1 s
  (higher in 2).
  Its recall on the 15 attack runs falls from 0.94 to 0.85 at 0.1 s; both hybrids keep 0.95 or more.
- Network-only is slightly higher at 0.1 s (+0.010, 8 of 10): the same recall on malware (0.52), attacks 0.99 →
  1.00, and fewer false alarms on the 18 network-active benign runs (0.35 → 0.29).
- The timing baselines do not rise. Host active windows alone: 0.588 (0.5 s), 0.616 (0.25 s), 0.573 (0.1 s).
  Network active windows alone (the number of windows with traffic): 0.719, 0.697, 0.681. That second baseline
  is new here: at 0.5 s it is only 0.04 below the network detector (0.756); at 0.1 s the gap is 0.085.

### Paper dataset, Table IV (held-out split): BA at forest seed 42 (TN/FP/FN/TP); mean over seeds 42, 0–9

| variant | host | network | concatenated | stacked |
|---|---|---|---|---|
| 0.5 s (published) | 0.929 (24/4/0/26); 0.927 | 0.750 (28/0/13/13); 0.750 | 0.926 (26/2/2/24); 0.926 | 0.963 (27/1/1/25); 0.932 |
| 0.25 s matched | 0.911 (23/5/0/26); 0.911 | 0.750 (28/0/13/13); 0.750 | 0.926 (26/2/2/24); 0.926 | 0.945 (26/2/1/25); 0.945 |
| 0.25 s mixed | 0.929 (24/4/0/26); 0.927 | 0.750 (28/0/13/13); 0.750 | 0.926 (26/2/2/24); 0.926 | 0.963 (27/1/1/25); 0.934 |
| 0.1 s matched | 0.929 (24/4/0/26); 0.917 | 0.750 (28/0/13/13); 0.750 | 0.886 (27/1/5/21); 0.886 | 0.963 (27/1/1/25); 0.949 |
| 0.1 s mixed | 0.929 (24/4/0/26); 0.927 | 0.750 (28/0/13/13); 0.750 | 0.926 (26/2/2/24); 0.926 | 0.963 (27/1/1/25); 0.935 |

The network detector makes the same 54 decisions at every window length. On this one split the concatenated
hybrid at 0.1 s matched misses 3 more of the 26 test malware (0.886); with the host columns at 0.5 s (mixed) it
is unchanged. Prologue-free rows are in `scores.txt` (host 0.929 → 0.911 → 0.875 at seed 42 from 0.5 to 0.1 s;
one split of 54 test rows).

### Session dataset (host at 0.5 s, network at the window shown): balanced accuracy

| span, network window | host | network | concatenated | stacked |
|---|---|---|---|---|
| 20 s, 0.5 s (base/20261117c) | 0.814 ± 0.017 | 0.735 ± 0.023 | 0.870 ± 0.025 | 0.840 ± 0.022 |
| 20 s, 0.25 s | 0.814 ± 0.017 | 0.738 ± 0.019 | 0.870 ± 0.024 | 0.837 ± 0.022 |
| 20 s, 0.1 s | 0.814 ± 0.017 | 0.736 ± 0.017 | 0.870 ± 0.021 | 0.839 ± 0.024 |
| 80 s, 0.5 s | 0.857 ± 0.014 | 0.776 ± 0.014 | 0.887 ± 0.014 | 0.862 ± 0.015 |
| 80 s, 0.25 s | 0.857 ± 0.014 | 0.779 ± 0.015 | 0.886 ± 0.014 | 0.863 ± 0.016 |
| 80 s, 0.1 s | 0.857 ± 0.014 | 0.770 ± 0.021 | 0.888 ± 0.016 | 0.863 ± 0.015 |

- Concatenated minus host stays +0.056 (10 of 10) at 20 s and +0.030 (10) at 80 s at every window; stacked minus
  host +0.023 to +0.026 (9) at 20 s.
- Per stratum nothing moves by more than 0.03 (attack recall of the network view 0.99 at 20 s at every window).
- The C2 subset (43 implants against all benign) loses a little in the network view: 0.687 → 0.665 at 20 s,
  0.829 → 0.791 at 80 s (stacked 0.824 → 0.796, 0.904 → 0.882). The network view's C2 result rests on the
  sinkhole's silent listener (not credited, `../session-lab/`), so this is not a loss of credited detection.

### The block rule's flood threshold at shorter windows

`block_policy.py` scales the flood threshold linearly: 500 active flows per 0.5 s → 250 at 0.25 s → 100 at 0.1 s.
With the TTL at 3 windows the benign maxima shrink with the window (network-active benign 231 → 118 → 49; CLI
benign 1), while the attacks with long-lived flows keep theirs (Slowloris and GoldenEye 150–1,017 at every
window). Attack runs above the scaled threshold: 10 of 15 at 0.5 s, 11 at 0.25 s, 12 at 0.1 s; malware 1 of 99
(the scanner) at every window. The three UDP sink floods (one flow each) stay below at every window.

## Reading

- On both datasets, 0.25-s or 0.1-s windows change detection by at most about 0.02 in balanced accuracy, within
  the spread over fold assignments. The hybrids' lead over host holds at every window.
- The detectors must be trained on rows built at the same window length as the rows they score: the means,
  standard deviations and active-window counts change with the window. The 0.5-s forests (features.csv,
  `live_test/streaming/dataset_windows.csv.gz`) cannot score 0.1-s rows.
- Host and switch windows do not have to match. Host at 0.5 s with the switch at 0.1 s ("mixed") scores as well as
  or slightly better than matched windows (concatenated 0.821, stacked 0.825), and it is the only design the
  session dataset allows.
- Limits: these are the release's offline models of the switch and the monitor; the hardware's 0.1-s and 0.25-s
  rows still have to be compared with them. The session host columns could not be rebuilt. The prologue-free
  variant removes the launcher from the rows afterwards (as in `../launcher-ablation-05s/`), not from a live
  launch. The Table IV numbers are one split of 54 test rows.

## Flood containment by window length and alarm delay (added after PC1 parts 11-13)

`containment.py`: the share of each dataset flood's frames from the host (10.0.0.10) sent after a host block,
for the 15 attack runs' own captures. The block comes D after the end of the first window that holds the
attack's traffic (every flood alarms on its first window with traffic at every length: PC1.md 12A, 12B). The
model reproduces PC1's numbers at 0.5 and 0.25 s: 55 / 71% at D = 50 ms (PC1 12B: 55 / 71%), 49% at 0.5 s and
213 ms (12A measured: 48%), and 0 / 40 / 36% for syn_fan_40k / udp_sink_60k / goldeneye_p10 at 0.5 s and about
270 ms (11E measured: 0 / 38.9 / 35.9%). At 0.1 s and 50 ms it gives 80%, where PC1's 12B has 83%: the two
GoldenEye runs send their first frame 0.18-0.20 s after the sample start, so their first 0.1 s window with traffic is
window 1 or 2. Blocking every flood after window 0, as 12B does, gives 83% (`window0` in `containment.json`).

Correction (2026-11-20, after PC1.md part 13K): the first version of `containment.py` blocked every flood after
window 0, although this table already used the first window with traffic; the 0.1 s column of that first
`containment.json` was 66 / 70 / 78 / 83% (270 / 213 / 100 / 50 ms). The script now writes both, and the 0.5 and
0.25 s columns are the same under both rules.

| alarm delay after the window | 0.5 s | 0.25 s | 0.1 s |
|---|---|---|---|
| 300 ms (PC1 13L: the stacked detector at 0.25 s, overlapped loop) | 46% | 55% | 61% |
| 270 ms (PC1 11E/11F: ~107 ms for the window to reach the collector, ~160 ms of scoring) | 47% | 56% | 62% |
| 226 ms (PC1 13L: the network detector at 0.25 s, overlapped loop) | 48% | 58% | 65% |
| 213 ms (PC1 12A median) | 49% | 59% | 66% |
| 100 ms | 53% | 67% | 74% |
| 50 ms | 55% | 71% | 80% |

At 0.25 s the delay is longer than the window: cutting it to 50 ms adds 15 points, going on to 0.1 s at today's
delay 6. The fan-out SYN flood syn_fan_40k (0.73 s long) goes from 0% blocked (0.5 s, 270 ms) to 28% (0.25 s,
270 ms), 58% (0.25 s, 50 ms) and 79% (0.1 s, 50 ms).

PC1.md part 13B (the host half of the 0.25-s table) was run here with PC1's `live_test/streaming/host_windows.py`
and `--index` (its search of `--root` stops on a malformed Go test zip under `committee-eval-20261113/toolchain/`).
240 of 240 runs equal the training table at 0.5 s; the start is `sample_started_monotonic_ns` in all 240. Its
`dataset_windows_0.25s.csv.gz` is text-identical to `run-20261120/dataset_windows_250ms_ascollected.csv.gz`
(902,400 cells).

## PC1 parts 13C/13K checked and part 12B rerun (2026-11-20)

- `check_13ck.py` (standard library): 13H's claims about the 0.25 s table on these files, and 13J/13L's timing and
  floods from the raw files of PC1's part 13, 13C and 13K archives. Output `check-13ck-20261120/`. Everything
  reproduced. The 13L table's medians are medians of the per-run medians, without each run's first marker.
- `rerun_12b.py`: PC1's 12B offline study (`study_windows.py`, copied verbatim) reproduces 12B: the same first alarm
  and blocked share in all 110 runs at every length. Probabilities differ by up to 0.07 (scikit-learn 1.7.0 here,
  1.9.1 on PC1, not checked).
  - 12B trained on the 110 runs with traffic only. All 43 benign among them send in their first window, so the forests
    alarmed on an empty first window (p = 1.000): 14 malware runs at every length, the two GoldenEye runs at 0.1 s.
  - Trained on all 240 runs (the live detector's population), or with alarms only from the first window with traffic:
    malware 82% blocked (12B: 89%), floods 55 / 71 / 78% (12B: 55 / 71 / 83%), goldeneye_p10 at 0.1 s 66% (12B: 100%).
    An empty window then scores at most p 0.45. On all 240: BA 0.738, as PC1's 12C network A.
  - Output `rerun-12b-20261120/` (`rerun_12b.md` has the table).
- Both scripts and their outputs are in p4_ebpf `819af0a` (`live_test/committee_replay/ws_20261120_check13_rerun12b.tar.xz`),
  with PC1.md's new section "Results, parts 13C/13K checked and 12B rerun" and corrections in 12B, 13J and p4_perf.md.
  The detector-based 0.1 s figure (78%) is below this folder's timing model (80%, first window with traffic), because
  goldeneye_p10's first 0.1 s window with traffic scores 0.22 and its alarm comes a window later.
