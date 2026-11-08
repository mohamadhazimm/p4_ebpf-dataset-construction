# Consolidated findings — P4/eBPF hybrid malware detection

Written 2026-11-03, after E1–E6 (and E5b) finished. This maps every experiment to the question it
answers, states the honest verdict, and lists what is still open. Numbers are copied from PLAN.md and the
per-experiment result files; nothing here is new analysis. The paper is already submitted (deadline Nov 2);
these results are for the thesis and for supplementary material (GitHub / camera-ready / a journal extension).

The dataset and models are the released ones (p4-ebpf-malware-detection): 240 executions, 90 host +
145 network columns, random forests (500 trees, balanced, seed 42, threshold 0.5). Table IV = held-out
malware-vs-benign split. Table V = grouped nested CV, ten fold seeds (42, 0–8), inner seed 7, logistic
stacker. Nothing is tuned on test data. A second dataset (E6, nginx-served) is kept separate, not merged.

## One-line verdict per experiment

| # | Question | Verdict |
|---|----------|---------|
| E1 | Does the deployment eBPF monitor produce the same host features as the dataset collector? | Yes — 27/28 workloads bit-identical, all decisions identical. The host sensor is deployable. |
| E2 | Does fusion beat host alone, and does detection generalize across attack types/families? | Fusion's edge is small and borderline; network generalizes across flood variants but not to the unseen slow-rate attack. |
| E3 | Is the idealized switch model a faithful proxy for the real switch? | For detection, yes (identical at every readout cap), though ~19% of individual feature cells differ. |
| E4 | Does background traffic break the network view, and can training fix it? | Background collapse is a training-data problem; trained with background, the hybrid is the most accurate of all (0.964). |
| E5 / E5b | Do the features survive encryption? | Benign TLS: yes, no false positives. Encrypted attack: payload-independent ≠ encryption-invariant — needs encrypted examples in training. |
| E6 | Did the Sink's connection limit distort the dataset? | It shaped attack/network-benign feature values but did not change headline detection; nginx is a cleaner second dataset with the same conclusions. |

## Per experiment

### E1 — in-kernel monitor vs dataset collector (VM)
27 of 28 matched workloads give feature vectors identical to the dataset collector (20157/20160 window
cells). The 3 differing cells are run-length/transition features in one 8-thread workload, from thread
interleaving. Total syscall counts match in all 28; every detector decision matches (max prob diff 0.0);
no events lost. **Use:** the monitor that would run in deployment reproduces the dataset's host features, so
the host-side results are not an artifact of the collection harness. Attempt: `kernel_check/20261103T170924343342Z`.

### E2 — generalization, fusion, lineage, uncertainty (offline)
- **Generalization (E2a):** leave-one-attack-type-out exposes a gap. Held-out slowloris recall collapses
  (stacked 0/50, network 5/50); held-out goldeneye is fine (stacked 20/20); held-out floods are caught by
  network. Network attack detection generalizes across volumetric flood variants, not to the unseen slow-rate type.
- **Fusion (E2b):** on identical folds, mean-of-probabilities 0.831, stacked 0.823, concat 0.812,
  host 0.784, network 0.756. The simple mean edges out the stacker; both beat concatenation.
- **Lineage (E2c):** leakage is small. Table IV without Tsunami/RapperBot test samples: host 0.929, hybrid 0.905.
  Merging Tsunami→Kaiten and RapperBot→Mirai in Table V: stacked 0.837, host 0.799.
- **Uncertainty (E2d):** Table IV hybrid−host diff −0.006 [−0.096, 0.086] (indistinguishable);
  Table V stacked−host diff 0.036 [−0.001, 0.081] (marginal). **The hybrid's edge over host is small and borderline.**

### E3 — switch-faithful feature model (offline)
Faithful model: CRC-16 buckets with collisions, IPv4 lengths, 32-bit ns timestamps that wrap at 4.295 s,
readout cap. ~19% of network cells differ from the idealized model, concentrated in flow duration (the wrap;
slowloris 18.5 s → 2.4 s) and byte magnitude (IPv4 vs Ethernet length). Detection unchanged at every readout
cap (None/5000/1000/350): Table IV host 0.929 / network 0.750 / hybrid 0.926; Table V 0.784 / 0.754–0.759 /
0.821–0.822. **Use:** the idealized model is a faithful detection proxy for the switch. **Caveat:** on a busy
deployment where many benign flows compete for the readout budget, the cap could matter more than this
quiet-host data shows. Faithful datasets: `e3_data/`.

### E4 — training with background traffic (VM)
150 training executions recollected with a benign background workload present. Table IV setting, 150 train /
54 test, four train→test combinations (BA, specificity):

```
quiet->quiet  host 0.929(0.86)  network 0.750(1.00)  hybrid 0.926(0.93)   [released Table IV]
quiet->bg     host 0.929(0.86)  network 0.500(0.00)  hybrid 0.500(0.00)   [network+hybrid flag everything]
bg->bg        host 0.911(0.82)  network 0.720(0.79)  hybrid 0.964(0.93)   [recovered; best hybrid]
bg->quiet     host 0.911(0.82)  network 0.500(0.00)  hybrid 0.946(0.89)
```

The network view's collapse on a busy host is a **training-data problem, not a feature problem**: trained
with background present, the network view recovers and the hybrid is the most accurate of all combinations.
The network view alone stays sensitive to whether train/test background match; the hybrid absorbs this and
the host view is stable throughout. **Takeaway:** fusion + training matched to deployment conditions gives
background-robust detection. **Caveat:** single split, 54 test executions, one background pattern.
Attempt: `background_train/20261103T173237830829Z`.

### E5 / E5b — encrypted traffic (VM)
- **Benign TLS (clean, E5 + E5b):** for benign pairs that did the same work over HTTP and HTTPS, the
  detectors classified the HTTPS run the same as the HTTP run — benign stayed benign. Feature values shifted
  (22–71% median relative change from handshake/record overhead) but not enough to flip a decision. **Features
  are payload-independent and benign TLS does not by itself cause false positives.**
- **Encrypted attack (E5b, equal strength on nginx):** with the attack running at full rate, encryption
  alone changed the flow statistics enough that a network detector trained only on plaintext slow attacks
  missed the encrypted slowloris (network 0.77→0.41 at 300 sockets; 0.78→0.44 at 800). **Payload-independent
  is not the same as encryption-invariant: detecting encrypted attacks needs encrypted examples in training.**
- **Confound surfaced:** INetSim caps concurrent connections at 10 (hard max 30). The original dataset's
  slowloris partly reflects that limit (network ~0.77 against an unlimited server vs 0.92–0.98 in the dataset).
  E5's attack-side TLS comparison was inconclusive until E5b removed the limit with nginx.
- **Caveat:** two attack pairs from one tool; indicative only. A clean encrypted-attack benchmark needs a
  real TLS server that lets the attacks run at full rate.

### E6 — nginx-served dataset (VM, offline analysis)
240 samples recollected against nginx (web, no connection limit) + INetSim (mail/FTP) + dnsmasq; 238 accepted
(2 GoldenEye rejected for capture overflow against the unlimited server). Paired change vs the original run:

```
malware      99  net 0.00  host 0.00  flips 1
cli benign  105  net 0.00  host 0.00  flips 0
null          3  net 0.00  host 0.00  flips 0
net attack   13  net 0.33  host 0.00  flips 2   (slowloris_800, slowloris_1000)
net benign   18  net 0.62  host 0.67  flips 3   (session_300, bulk1000, bulk1600)
```

The server only matters for Sink-dependent runs (attacks, network-active benign); malware, CLI-benign and
nulls are unchanged. 6 of 238 runs flip a decision, all in the networking tail. Aggregate detection is nearly
identical: Table IV host 0.929→0.893 / network 0.750→0.750 / hybrid 0.926→0.945; Table V 0.784→0.782 /
0.756→0.757 / 0.823→0.806. **The connection-limit confound was real but not consequential; nginx is a
cleaner, more realistic second dataset that reaches the same conclusions.** Reported side by side, not merged.
Attempt: `nginx-dataset/20261103T183218692466Z`.

## Thesis-level synthesis (three separately-true pieces, honestly scoped)

1. **Host eBPF syscall-sequence features detect general Linux malware.** Robust within-training grouped-OOF
   ~0.72; single held-out draw ~0.93 (optimistic). The ADFA-90 descriptors carry the signal.
2. **Network/P4 flow features cleanly detect volumetric DDoS/flood traffic.** CIC-DDoS2019 seven attack
   types ≥ 0.998; the live Kaiten SYN-flood-vs-benign-bulk capture shows network flow-shape separates a
   malicious flood from benign bulk where host syscall activity cannot.
3. **The hybrid's genuine additive value is situational, not a blanket accuracy gain.** It helps on
   (a) false-alarm reduction for network-busy processes, and (b) background robustness when trained to match
   deployment (E4). On general malware the hybrid is statistically indistinguishable from host alone (E2d).
   It does **not** show broad hybrid-over-host superiority, and it does not show host-evasion (floods are host-loud).

## Open items / future work

- **Clean encrypted-attack benchmark.** Needs a real TLS server that lets the attacks run at full rate
  (INetSim/this lab cannot). The E5b result is indicative, two pairs, one tool.
- **Switch hardware deployment on netlab.** Already scoped as future work; E3 shows the offline model is a
  faithful detection proxy, so this is an engineering/validation step, not a correctness risk.
- **Busy-deployment readout-cap effect.** The quiet-host data cannot show whether the switch's readout budget
  matters when many benign flows compete; measure on a loaded deployment.
- **HTTPS network batch for the nginx dataset.** Small loose end from the E6 plan; E5b already covers the
  slowloris/benign HTTPS-vs-HTTP comparison against nginx, so this is optional.
- **Deployment-caveat paragraph.** The p4_ebpf live_test flagged deployment-collector issues (in RESULTS.md);
  worth a short honest paragraph in the thesis deployment section.

## What's left for the thesis

- Results/discussion chapters built on the verdicts above, keeping every caveat intact.
- A limitations section: single splits where noted (E4), one background pattern, one attack tool for the
  encrypted-attack pairs, in-distribution CIC benign, dormant-C2 malware.
- The deployment-caveat paragraph citing the live_test findings.

---
## 2026-11-04 — Guard against a single-split misread (nginx Table IV)
The nginx recollection's Table IV shows hybrid 0.945 / host 0.893, which looks like "hybrid finally beats host." It is single-split noise: on a 54-execution test split that is 3 samples moving (host +2 benign FP, hybrid +1 malware TP). The robust repeated grouped CV (Table V design) on the nginx data gives host 0.782+/-0.016, hybrid-stacked 0.806+/-0.027 — host did NOT fall to 0.89 and hybrid did NOT rise to 0.945. The honest, defensible hybrid result (both datasets) is a small consistent edge: hybrid-host = +0.039 (9/10 seeds) INetSim, +0.024 (8/10 seeds) nginx. Thesis must report the robust paired delta with spread, never the Table IV cell, as the hybrid-vs-host claim. See PLAN.md E6b.
