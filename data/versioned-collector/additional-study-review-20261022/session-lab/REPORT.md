# Session lab: attacks injected into normal activity, network recorded outside the guest

Status (2026-11-17 07:10 UTC): finished. Every run is collected and analysed, the pooled base dataset is built
(`base/20261117/`, README there), and the dataset's programs are scored on the paper's held-out split
(`analysis-dataset-cohort/`). The thesis note with every number and its caveats is the thesis repository's
`data/lab/session_lab.md` (numbers in `data/lab/session_lab.json`).

## Why

The dataset's lab had five measured problems (DESIGN.md): malware saw our collector and quit (5 held-out Tsunami
bots), only malware left connections unanswered (the network detector leaned on it), benign and malware came from
separate batches in later cohorts, benign programs ran short and alone, and some malware started after the 20-s
window. The session lab copies LID-DS 2021's structure for host malware: normal activity runs the whole time and the
attack arrives at a known time inside it.

## How a session works

- One boot of the quiet headless guest, restored from its baseline (`clean-final-quiet-v19-20261024T150104720304Z`)
  for every session; 180 s; after the session the guest is powered off, and the original clean snapshot is restored
  at the end of each run.
- Background activity (guest/bg.sh, seeded per session, as the guest user, own cgroup app-a): a web check-in to the
  Sink, browsing and downloads to the Sink and to documentation addresses (RFC 5737), DNS bursts, the guest's own
  command-line jobs (hashing, compressing, archiving, searching, listing, grep), one NTP poll nobody answers and one
  TLS poll. Pilot: check-in every 10 s; main collection: the same script 4 times faster (check-in every 2.5 s).
- One program injected at a seeded time in 40-100 s (cgroup app-b, as the guest user, the dataset's launch wrapper,
  stdin /dev/null, own session, from a neutral /tmp/<random> folder): a dataset malware sample, a dataset benign task
  with its own arguments and input files, a flood generator, a null program, or nothing (the time is then a pseudo
  time). Attack and control sessions are interleaved in one run.
- The Sink answers everything: INetSim (HTTP, HTTPS, mail, FTP), dnsmasq answering every name with 203.0.113.200,
  and the passive sinkhole redirecting every other TCP connection to a listener that accepts and stays silent.
- Host: two hostmon_agg (named sysstatd) count each cgroup's system calls in the kernel per 0.5-s window from a
  shared start; sockowner (netcfgd) records every socket's flows with its process and cgroup. No Python runner,
  bpftrace or tcpdump in the guest; the root script that starts them sleeps while the program runs.
- Network: tcpdump on the Sink, the guest's gateway (the switch's vantage point), with its received / captured /
  dropped counters. Clock probes (UDP, guest clock in the payload) before the start and after the end map the guest's
  monotonic clock onto the capture clock (the two VMs' clocks drift by about 0.05%, mapped linearly).
- Per session: technical checks (session status, both monitors' windows and health, sockowner health, capture
  counters, probes, the injected program's SHA-256). Pilot: stop at the first failed check; main: record and go on,
  three in a row stop the run.

## Analysis

- analyze_session_lab.py: per session, the checks above, every guest flow on the wire matched to its owner
  (background, injected program, or nobody; DNS the guest's stub resolver relays is given to the cgroup that asked it,
  matched by time), and per-window host (18) and switch (29) features with the release's code, for the whole machine
  (both cgroups, all traffic) and for the injected program alone (its cgroup, its own flows).
- compare_session_lab.py: (A) each dataset malware sample's behaviour in its dataset run vs its session vs Triage's
  internet run; (B) benign tasks, session vs dataset row; (C) detection on per-program rows (the injected program's
  first 20 s, as long as a dataset run; also 80 s): the paper's detectors trained on the 240 dataset rows applied to
  session rows, and grouped cross-validation within the session rows; (D) LID-DS-like detection on 10-s machine
  windows (both cgroups, all traffic, the window starting 2 s before the injection; the same session's window 22 s
  earlier as a normal window); (E) the lab cue (a connection left unanswered) on per-program rows.
- Planned in DESIGN.md ("Evaluation") and added to compare_session_lab.py after the interim look: one-feature
  baselines for activity (log of the program's system calls), lifetime (windows with host activity), injection
  time, batch (pilot or main) and execution mode, each next to the BA of random noise features under the same folds
  (20 draws); seen-family folds (stratified, a family's rows in training and test) next to the grouped
  (unseen-family) folds; the hybrid-minus-host BA per fold assignment; the share flagged per family / project;
  for the machine windows also a position baseline (where in the session the window lies). The per-program rows are
  written to program_rows_20s.csv.

## A known difference from the dataset's lab: how the program starts

In every dataset run the injected program's first window also holds the calls of the Python runner's child process
before it executed bash (75 calls in the dataset's null run and in a malware run alike: close, three dup2, chdir, 63
rt_sigaction of which 54 in a row, three rt_sigprocmask, setsid, two close_range and the execve of bash), then bash's own start (103 calls). The session lab starts the program from a bash that waits on a
FIFO and is released at the injection time; the Python part is missing. On the rows: the longest run of one call
(`host_max_run_length_max__max`) is at least 54 in all 240 dataset rows and 12 to 17 for quiet session programs; the
distinct calls among the first 50 (`host_first50_unique_mean__max`) are 5 in a typical dataset row and 21 in the
sessions; among the first 100, 15 and 22. The paper's detectors, trained on the dataset rows, learned this start-up
(as the live test on PC1 showed, 2026-11-04): applied to session rows they flag many quiet benign programs. The
transfer test is therefore also reported without the six columns of these three signals (a post hoc diagnostic).
Detection trained and tested within the sessions is not affected: every session program starts the same way.

## Results

Runs (attempt folders under `runs/`; each has `protocol.json`, per-session folders and its analysis):

| run | attempt | sessions | accepted | note |
|---|---|---|---|---|
| pilot | `20261115T213142604626Z` | 20 | 20 | 1x background; s01 accepted on a corrected probe check |
| main | `20261115T214153675625Z` | 163 of 254 (deadline) | 155 | the dataset's 99 malware (28 families) and 105 benign tasks; 3 floods rejected, 5 boot hangs |
| network-active pilot | `20261116T100129450384Z` | 33 | 33 | one sample of each of 13 Triage network-active families |
| floods | `20261116T124104912903Z` | 28 | 27 | SYN/UDP/Slowloris/GoldenEye/HTTP floods and network-active benign |
| Triage cohort | `20261116T153432251861Z` | 107 | 104 | 54 malware of 13 Triage families (capped), 44 benign, 9 controls |
| rest of the main plan | `20261116T223142789936Z` | 105 | 105 | main's 91 unreached + 5 never-booted sessions, the pilot's 9 dataset malware again |

Every guest flow was attributed to its cgroup (DNS relayed by the stub resolver given to the asking cgroup); Sink
captures had received = captured and no drops in every accepted session; both monitors' health counters were zero
apart from the capacity-only overflows of scanner and flood sessions (accepted for malware/attack sessions under the
rule their protocols declared). Malware is named by family and an 8-hex prefix only.

Behaviour (main, `analysis-final/comparison.json`): of the dataset malware that started, 45 of 69 used the network
and every connection got an answer; 7 dataset-silent samples now run (Tsunami, DeskRAT: they had quit when they saw
the collector); 25 are silent in both (mostly ransomware that exits at start). No malware left a connection
unanswered, so the dataset's unanswered-connection cue is gone (that rule alone: BA 0.507). Benign tasks reproduce
their dataset rows at a median Spearman of 0.997 (61 tasks).

Detection per program (the injected program's own rows; grouped CV, families/projects held out, 10 fold
assignments; BA): main, 20 s host 0.80, network 0.72, concatenated 0.80, stacked 0.79 (families seen: 0.86/0.76/
0.86/0.88); baselines 0.49-0.61, random features up to 0.52. Whole-machine 10-s windows score 0.79 (stacked) as
placed but 0.57-0.62 for every detector at matched session positions: window position, not the malware. The paper's
detectors transferred to session rows flag many quiet benign programs because the dataset's Python launcher start-up
is a host feature the sessions lack; without the six start-up columns host specificity 0.58 -> 0.83.

Floods (`runs/20261116T124104912903Z/analysis/flood_scores.json`): the paper's network detector, unchanged, catches
SYN 3/3, UDP 3/3, Slowloris 3/3, GoldenEye 3/3 with no false alarm (BA 0.962) and misses the HTTP flood 0/1 (a type
the paper never had). With flood examples in training: concatenated 0.88, host 0.87, network 0.84 (host 0.95 at
80 s); a never-seen attack type is harder (network 0.70 at 20 s, 0.78 at 80 s).

Table V reproduced (`runs/20261116T124104912903Z/analysis/pool_tablev.json`): the main run's general malware with
the floods in Table V's structure (60 general malware + 15 floods vs 69 benign, 20 s): host 0.805, network 0.721,
concatenated 0.827, stacked 0.823 (paper 0.784 / 0.756 / 0.812 / 0.823), with the same split of roles (network
flood recall 1.00, host general-malware recall 0.72).

Triage cohort (`runs/20261116T153432251861Z/analysis-final/`): 53 malware (13 families) vs 46 benign, 20 s: host
0.853, network 0.814, concatenated 0.831, stacked 0.876 (80 s: 0.937 / 0.929 / 0.959 / 0.973); lifetime baseline 0.73
(20 s) and 0.82 (80 s). The pre-registered question, whether the network view catches the host-quiet C2/backdoor
implants that the host view misses: yes at 20 s. Host misses Rekoobe 0/6, AdaptixC2 0/2 and most Sliver; network
catches them. On the 35 implants against the benign: host 0.810, network 0.854, concatenated 0.838, stacked 0.932
(+0.122 over host in 10/10 assignments). Two limits: trained on all 13 families both hybrids drop Rekoobe again
(stacked 0.23), and by 80 s the host view catches up. Network false alarms on network-active benign are the cost
(specificity 0.35; 0.60 with the network-active pilot's 13 benign clients added). Families were chosen because they
network, so this shows that these implants are visible on the network, not a general C2 recall.

A new lab cue (post hoc, `silent_server_check.py`, `silent_cue_crosstab.py`, results in `analysis-silent-server/`):
the sinkhole's catch-all listener accepts and never sends data, and only malware met it (main run: 30 of 34 networking
malware; Triage+pilot: 40 of 43 C2 implants; benign: 2 of 125 programs, telnet tasks that sent nothing). The rule
"a server accepted and then stayed silent" alone scores BA 0.73 on the main run (network detector 0.71-0.72) and
0.93-0.96 on the implants (network detector 0.84-0.85). The network detector follows it: it flags 97% of the main
run's malware with the cue and 15% without; within Sliver, vshell and Ladvix it flags the implants whose server
stayed silent in 92-100% of assignments and those whose server answered in 0-20%. So the session lab's network
results on general malware and on C2 implants are not traffic-shape evidence (the unanswered-connection tell was
replaced by an accepted-then-silent one); the host view's results and the floods (aimed at the Sink's own address)
do not depend on it. A future collection needs a sinkhole that answers unknown ports with data, and benign clients
that meet such servers too.

Rest of the main plan (`runs/20261116T223142789936Z/analysis-final/`): 105 of 105 accepted overnight (22:54-06:07
UTC), no boot hang, every phase passed, the Sink restored. With the main run, every program of the dataset cohort
now has exactly one accepted session under the main settings: the 99 malware, the 6 the dataset rejected, and the
105 benign tasks. One session (Mirai `0882f75e`) first failed the analysis because the sample renamed its processes
with a vertical tab, which `str.splitlines()` treats as a line break. `analyze_session_lab.log_lines()` now splits
at newline only. Of 1,347 monitor and tracer logs, only that one contains such a character, and the other 104
sessions' analyses are identical.

Dataset cohort, main + rest (`base/20261117/dataset-programs/comparison.json`): all 105 dataset malware re-run, 100
started, 60 networked with every connection answered; 7 dataset-silent samples now network (5 Tsunami, 2 DeskRAT);
benign median Spearman 0.997 over all 105 tasks. Per program, families held out, 20 s: host 0.80, network 0.72,
concatenated 0.81, stacked 0.80 (families seen: 0.91 / 0.77 / 0.93 / 0.92); baselines <= 0.60.

The paper's held-out split (Table IV) on those session rows (`dataset_cohort_heldout.py`, protocol written before any
score; `analysis-dataset-cohort/heldout.txt`), forest seed 42 / mean of 11 seeds: host 0.893 / 0.898 at 20 s and
0.927 / 0.927 at 80 s (Table IV 0.929 / 0.927), concatenated 0.964 / 0.956 (0.926), stacked 0.893 / 0.894 and
0.927 / 0.929 (0.963 / 0.932). The network view's 0.827 is exactly the silent-listener rule (same decisions; 17 of
17 catches met it). On this split the 20-s activity baseline is 0.765.

Base dataset (`base/20261117/`, every run under the main settings, one acceptance rule): 361 program rows, 182
malicious (98 dataset malware, 2 it rejected, 66 Triage malware, 16 attacks; 40 families) vs 179 benign and
controls. Grouped CV, 20 s: host 0.854, network 0.769, concatenated 0.869, stacked 0.886 (stacked - host +0.032,
10/10); 80 s: 0.903 / 0.775 / 0.894 / 0.905 (stacked - host +0.002). Network flood recall 1.00, network specificity on
network-active benign 0.44. Over the whole base the network view flags 99% of the malware that met the silent
listener and 15% of the rest (benign 18%), so outside the floods its malware detection is the cue. The C2 implants
against all benign: host 0.77, network 0.84, stacked 0.91 at 20 s; 0.92 / 0.92 / 0.98 at 80 s.

## Two benign batches and the final base (2026-11-17)

- **Silent-server benign** (`runs/20261117T013400746805Z`, 24/24 accepted): 18 benign clients aimed at the sinkhole's
  silent listener. Pre-registered (`score_silentbenign.py`): with them, the network view's implants-only BA falls from
  0.838 to 0.658 and its Rekoobe recall from 0.96 to 0.06; the network view is **not credited** with C2 detection
  beyond the cue. Base rebuilt as `base/20261117b` (382 rows).
- **Network-active benign** (`runs/20261117T113428913222Z`, 59/62 accepted, 3 boot hangs; a first attempt
  `20261117T105520781257Z` stopped after 5 sessions because the lab's dnsmasq refuses AAAA and musl clients then fail
  the lookup): 53 benign clients of 8 programs (curl, wget, OpenSSL, telnet builds; the two lab tools; a Go and a Python
  transport client) against answered servers, incl. our test server on the Sink for this batch. Behaviour check 54/54
  as designed; 3 repeats match their earlier sessions (0.985-1.000). Pre-registered (`score_netbenign.py`): Q1 met
  (network specificity on the earlier network clients 0.34 -> 0.57 base, 0.33 -> 0.49 paper pool), Q2 met.
- **Final base** `base/20261117c` (435 rows, 182 vs 253; README there), 20 s: host 0.814, network 0.735,
  concatenated 0.870 (+0.056 over host, 10/10), stacked 0.840 (+0.026, 9/10); 80 s 0.857 / 0.776 / 0.887 / 0.862.
  The host view fell (0.842 -> 0.814): trained without the batch it flags every Go and Python benign client, so part
  of its earlier recall keyed on the runtime.
- **Cue split** (`cue_split.py` -> `base/20261117c/cue-split/`): of the +0.056 lead, +0.020 is earned on rows that
  met the silent listener, +0.037 on rows that never did, and about +0.020 (floods, rows without network traffic)
  cannot involve the cue. Without it the lead would lie between about +0.02 and +0.045. Decision (the author): no
  answering sinkhole and no re-run.
