# VM batches of 2026-10-31: analysis plan

Written before either batch was collected. The batches use the same collector, settings and quiet
baseline as the paper's dataset (runner `.21`, SHA-256 `4933ff5c...`, 20-s fixed observation, 0.5-s
windows, `enp0s3`, eBPF, common launch wrapper; snapshot `clean-final-quiet-v19-20261024T150104720304Z`).
Models, features, seeds and the 0.5 threshold are those of the paper; nothing is tuned on the new runs.
The dataset is `p4-ebpf-malware-detection/dataset/features.csv` (240 executions).

## Acceptance of a new run

Collection quality `accepted`, target exec observed, 40 telemetry windows with all 169 features finite.
Python batch: the workload's JSON summary on standard output reports success and the process exits 0.
Background batch: at least one marked background HTTP request (`/bg/`) inside the feature windows of
the capture. Runs that fail are reported and excluded; there are no retries or replacements.

## Batch P: benign Python workloads (16 runs)

Question: do the detectors flag Slowloris and GoldenEye because they run in the Python interpreter? These
are the only Python programs in the dataset. The 16 benign workloads are launched exactly like the two
tools (the `flood_gen pyexec` launcher execs `/usr/bin/python3` on a script staged beside it); 8 send
traffic to the Sink, 8 do local work only.

- P1 (primary). Fit host-only, network-only and the stacked hybrid on all 240 executions as in Table V
  (random forests with 500 trees, seed 42; the stacker is trained on inner out-of-fold probabilities from
  five grouped folds, seed 7). Score every accepted Python run. Report, per detector, how many runs are
  flagged (probability >= 0.5) and the mean probability, for the network and local halves separately.
- P2. Repeat the Table V cross-validation (ten fold assignments, seeds 42, 0-8) with the Python runs added
  as benign executions in one group (`benign_project::python-workloads`). Report the Table V metrics, the
  share of Python runs classified correctly, and the recall on the 5 Slowloris and 2 GoldenEye runs, next
  to the same quantities without the Python runs. The fold assignments differ once runs are added, so the
  two are compared per detector, not per fold.

## Batch B: concurrent benign background workload (90 runs)

Question: how much does traffic from other processes on the host change detection? The network features
describe all of the host's traffic; the host features describe only the monitored process tree. The batch
reruns, with the background workload active, the 54 held-out test executions of Table IV (26 malware,
28 benign) and the 36 executions of the attack batches (15 network attacks, 18 network-active benign,
3 null), using their original sample files and arguments.

- B1 (Table IV setting). Fit host-only (90 features), network-only (145) and the concatenated hybrid
  (235) on the 150 training executions exactly as in Table IV, score the 54 original test executions
  (this must reproduce Table IV) and their accepted background reruns. Report balanced accuracy, recall,
  specificity and AUC per detector for both, and the runs whose decision changes.
- B2 (Table V setting). In each of the ten fold assignments, every run in a test fold that has an
  accepted background rerun has the rerun scored by the same fold's models (host-only, network-only,
  stacked hybrid). Report, per class (malware, network attack, benign workload, network-active benign,
  null), the share of correct decisions for the originals and the reruns over all assignments, and the
  number of runs whose decision changes in at least one assignment.

Both batches are small; results are reported as counts and shares, with the number of distinct runs
stated next to the number of predictions.

## Amendment 1 (2026-10-31, before the second background attempt)

The first background attempt (`background/20261031T115525057283Z`) is preserved as `failed_preserved`.
Its background workload (v1) started at boot but died in its first iteration (cron log and the workload's
own log, read from one extra boot of that snapshot). The exception was not kept, because standard error was
discarded; the only call not protected by an error handler was the first DNS send, which fails while the
network is not yet up (reproduced in a test namespace). None of its 72 retrieved runs contains background
traffic in the feature windows, so none can be used for B1/B2. The attempt was stopped at 72 of 90.

Changes for the second attempt, nothing else: the workload (v2) catches errors in every iteration and keeps
running; the cron entry keeps standard error; the driver boots the staged snapshot once before collection
and refuses to collect unless the workload is alive and has logged at least 10 successful requests.

Added after the failure (not planned beforehand): the 72 runs of the first attempt are an unplanned rerun of
the same executions without background traffic. They are reported separately as a measure of run-to-run
variation, which the background effect must exceed to be attributed to the background workload.

## Amendment 2 (2026-11-03, before the continuation of the second background attempt)

The host machine went down on 2026-10-31 at about 14:18 UTC (no clean-shutdown record) during case 75 of
the second background attempt (`background/20261031T131605950427Z`) and came back on 2026-11-03. 74 of the
90 runs were retrieved; case 75 (`amd64_static-validation-wget-net-a-0a23aee0.zip`) was cut off before its
output was retrieved and 15 cases never started. The driver could not restore the VM; the guest was found
powered off on the batch's child snapshot and was restored to the original snapshot on 2026-11-03.

The remaining 16 cases (the interrupted one and the 15 never started) are run once more as a continuation,
in their original order, from the same frozen payload and child snapshot, with the same settings. Their
outputs go to `runs-continuation/`; the partial output of case 75 stays in `runs/`. The interrupted case is
run again because the host failed, not the sample; no other case is rerun. Before collecting, the
background workload is checked again by one boot of the child snapshot, as in Amendment 1.

Addendum (2026-11-03). The first continuation attempt stopped at its background check (preserved in
`run-continuation/`): the workload was alive but no request succeeded, because the host crash had also
stopped the Sink's services. The Sink (REMnux, user `remnux`, logged in on its console) was restored to its
2026-10-18 configuration, taken from its own journal of that boot: `sudo systemctl start inetsim` (INetSim
1.3.2, `/etc/inetsim/inetsim.conf` unchanged since 2026-10-04, SHA-256 53de0365...f30592; its DNS service
fails to start, as it did then) and `sudo /usr/sbin/dnsmasq --conf-file=/dev/null --no-resolv --no-hosts
--address=/#/10.0.0.1 --listen-address=10.0.0.1 --bind-interfaces --pid-file=/run/dnsmasq-hostpilot.pid`.
`accept-all-ips` stays off (empty NAT table), as during the collections. Checked from a clean guest boot:
HTTP 200 with the pinned 258-byte body (SHA-256 f0a3eec2...), and DNS answers authoritative, with recursion
available, TTL 0 and address 10.0.0.1, as in all 2000 answers of the original `dns_2k` capture.
