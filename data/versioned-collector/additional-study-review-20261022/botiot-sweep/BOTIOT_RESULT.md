# Bot-IoT cross-dataset network-feature result (2026-10-26)

Dataset: Bot-IoT 5% "All features" subset (UNSW 2018), 4 CSVs, 3,668,522 flows.
Tool: Argus flow features (NOT CICFlowMeter) — independent lab + independent flow extractor from CIC-DDoS2019.
Label reality: 3,668,045 attack vs **477 Normal (benign)**. DDoS 1.93M, DoS 1.65M, Recon 91k, Theft 79.
All offline, streamed from the zip (no extraction); payload-free flow features only (ports/IPs/protocol/timestamps dropped). No VM, no model promotion, no merge with the VM host+network cohort.

## 1. Within-Bot-IoT sweep (15 Argus per-flow features; RF200/seed42/5-fold BA)
`botiot_sweep_results.json`
- Normal vs DDoS: **0.998**
- Normal vs DoS: **0.999**
- Normal vs Reconnaissance: 0.944
- Normal vs Theft (n=79): 0.950
- Normal vs Any-Attack: 0.942
- Attack-type multiclass DDoS/DoS/Recon (8k/class): **0.996**
Benign-vs-attack tasks are capped at n=477/class (the dataset's benign ceiling).

## 2. Cross-dataset transfer (12 tool-INDEPENDENT features derived identically on both:
duration->s, total/fwd/bwd pkts & bytes, pkts/s, bytes/s, mean pkt size, fwd/bwd & down/up ratios; log1p)
`xdataset_transfer_results.json`
- within-CIC (benign vs attack, same 12 feats): BA 0.986
- within-Bot-IoT (benign vs attack, same 12 feats): BA 0.987
- transfer CIC -> Bot-IoT: BA 0.486, attack recall 0.008, benign spec 0.964
- transfer Bot-IoT -> CIC: BA 0.456, attack recall 0.025, benign spec 0.888

## Honest reading
- The payload-independent flow-feature FAMILY generalizes: it separates benign from volumetric
  DDoS/DoS at ~0.99 BA in TWO independent datasets, different labs AND different flow-extraction
  tools (CICFlowMeter vs Argus). The feature CHOICE is not a CIC/UNB artifact.
- A model FITTED on one dataset does NOT transfer zero-shot to the other (BA ~0.47-0.49; it labels
  almost everything benign on the foreign dataset, attack recall <3%). This is severe cross-dataset
  distribution shift: CIC reflection/amplification DDoS and Bot-IoT IoT-bot floods occupy different
  regions of the common flow-feature space even after unit normalization. This is a well-known
  cross-dataset NIDS limitation, NOT a weakness of the within-system detection claim.
- Net for the paper: use Bot-IoT as a SECOND independent confirmation of the network half
  (feature-family generalization, ~0.99 both datasets). Report the zero-shot transfer collapse as a
  limitation / future-work item (domain adaptation needed for cross-deployment transfer), not as a
  headline detector number.

## Caveats
- Bot-IoT benign n=477 (hard ceiling); benign-vs-attack numbers are small-sample.
- Network-only; no host side -> not mergeable with the VM host+network cohort (same as CIC).
- Within-dataset, same-capture benign; not a held-out-generalization claim beyond the transfer test.
