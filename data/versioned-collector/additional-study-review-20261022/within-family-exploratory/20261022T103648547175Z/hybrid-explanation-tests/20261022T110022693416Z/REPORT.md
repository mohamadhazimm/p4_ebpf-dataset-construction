# Hybrid Explanation Experiments

## Scope

User-authorized offline exploratory tests. Original data, roles, models and probabilities are unchanged. No VM operation, sample execution or collection. No alternative fitted model was scored on validation. All new model comparisons use only the 182 original training cases.

The data and hypotheses were previously examined. Frozen diagnostic choices prevent score-driven additions within this attempt, but do not make it preregistered blind confirmation.

## Theory

The best possible classifier with both sensors can ignore network features, so its minimum achievable population 0-1 risk cannot exceed that with host alone. A finite, greedily trained RF500 is not that optimal classifier. Extra noisy or redundant predictors alter feature sampling, split choices, variance and calibration. Strict benefit also needs useful conditional network information. Neither a hybrid win nor an OR-rule accuracy improvement is guaranteed.

## Findings

Completed 425 RF/ExtraTrees fits (212,500 trees) and ten nested logistic fusion fits. Saved outputs contain210 score vectors, including seed/prefix/permutation controls, not210 independent hypothesis tests. All new fits/evaluation used only the182 original training cases. Independent sklearn checks reproduced every confusion matrix, BA, AUC, Brier/log-loss and group-weighted BA;563 frozen input hashes passed. Original family-grouped OOF baselines reproduced exactly. Synthetic guards and editor checks passed.

### Implementation And Headroom

No tested matrix/export/imputation/label-order implementation error was found. Saved145/145/290 widths, exact probabilities (maximum error0), training-only MI, class order, training-median imputers and row-permutation consistency all pass. Only two of184 saved validation decisions favor host over hybrid, with none favoring hybrid. The descriptive exact paired p-value is0.5, not evidence of stable superiority, and is not a confirmatory test.

The two extra hybrid errors are malware GetShell `1dbfe7a5e6cf95ffdf056de416e40c9b47c47ce04bc347c66767184a5ce4cca0.zip` (host/P4/hybrid scores0.622/0.268/0.386) and benign `i386-net-tools-hostname.zip` (0.382/0.538/0.576). P4 points in the wrong direction in both, but concatenated forests are not averages of those scores, so this is not proof of a causal per-case mechanism.

P4 correctly classifies four of the six saved host errors. A label-informed oracle choosing the right standalone detector on each case would get182/184 correct; that oracle is not implementable from these results. Thus the evidence is NOT that network information is universally useless. It is that the current learned fusion does not reliably exploit its limited complementarity.

### Feature Competition And Weak Network Signal

Family-grouped training OOF BA is host92.94%, P464.20%, hybrid90.73%. Hybrid mtry24 improves to91.92%, but the matching host mtry24 control gets93.45%. Letting every column compete still gives hybrid90.73% versus host92.94%. Feature subsampling contributes sensitivity but does not explain the entire gap.

The zero-network family control gets92.94%, while shuffled-network gets90.14%, close to real-network90.73%. The top-five-training-selected network-family hybrid gets93.03%. These controls are consistent with a weak/high-dimensional block disturbing an already strong host representation; they do not prove all P4 features are noise or identify packet ownership. The full training matrix has25 constant host candidates and two constant P4 columns, not an entirely empty network sensor.

For the fitted family-OOF hybrid, ten whole-network block permutations average90.77% BA, compared with90.73% unperturbed; whole-host block permutation falls to60.22%. In unit OOF, network permutation averages94.06% versus94.64% unperturbed, while host permutation falls to51.76%. This supports predominantly host-driven predictions with limited marginal network utility, not a causal attribution claim: permutations can break realistic joint distributions. The prior benign attribution pilot independently demonstrated unrelated background HTTP, but this experiment does not establish every packet's origin.

### Fusion, Seeds And Related Cases

Nested logistic fusion reaches93.11% family OOF BA versus host92.94%, but96.09% unit OOF versus host96.68%. Its family-fold network coefficient changes sign in two of five folds, while the host coefficient stays positive. Fixed OR gives77.72% family OOF BA: false positives increase from8 to39 while false negatives decrease from5 to4. More alerts do not guarantee better accuracy or BA. Other fixed fusion rules, ExtraTrees, min-leaf regularization, log transforms and tree-count prefixes are all retained in the full table/results; no winner was selected or scored on validation.

In all three fixed seeds7/42/137, host beats hybrid in both unit and family OOF. In behavioral-cluster OOF, seed42 gives hybrid95.07% versus host94.39%, but seeds7/137 reverse that direction (host95.49%, hybrid94.56%). There are177 program/hash units,56 family/project groups and158 behavioral clusters among182 training cases. The sign is not stable under related-case grouping and stochastic variation. These behavioral clusters do not certify source-level malware lineage. Equal-group weighting also changes the estimand: family OOF gives host88.38% versus hybrid89.30%, unlike the sample-weighted ordering. Neither metric should be selected after seeing which favors hybrid.

### Activity And Post-Target Representation

Pre-target-only raw counts give50.85% unit OOF BA, versus96.17% for post-target counts and95.66% for post-target transitions. This does not support a launcher-only explanation for all discrimination. It also does not certify malicious behavior: loader, runtime, task, activity and ABI effects remain. In family OOF, pre-target counts get30.44%, post-target counts92.86%, and transitions95.66%; the below-chance result is preserved, not inverted to tune a classifier.

Activity-only unit/family BA is79.17%/65.56%. Removing a training-fitted linear component explained by log activity/mode/cohort lowers host family BA from92.94% to77.04%, and hybrid from90.73% to75.94%. Coarse activity reweighting also changes results. These diagnostic alterations remove potentially useful workload signal and change the fitted problem; their drops are NOT causal estimates of shortcut reliance. The independently documented activity-label association and cross-split collisions remain validity concerns.

### Unresolved And Not Claimed

This is a broad finite diagnostic battery, not every logically possible experiment. Source-level malware lineage certification, representative independently sourced benign tasks, general socket/process packet ownership, never-recorded-event completeness, attack activation and genuinely untouched evaluation are not established here. Existing reconstruction/quality audits are reused, not silently upgraded into new collection-completeness claims. No fresh VM-state claim is made.

No new validation threshold sweep, score-driven seed search, collection/retry, background suppression, original-case deletion or production change was performed. A future detector study needs reviewed lineage/task/activity groups, attributable/matched network tasks and untouched evaluation. The goal should be measured complementary value, not enforcing a hybrid win.

## Saved Implementation

```json
{
  "verification": {
    "status": "verified",
    "primary_cases": 184,
    "model_widths": [
      145,
      145,
      290
    ],
    "maximum_probability_error": 0.0,
    "training_only_selection_reproduced": true,
    "original_sources_and_models_unchanged": true,
    "split_unit_overlap": 0
  },
  "models": {
    "network_p4": {
      "metrics": {
        "samples": 184,
        "balanced_accuracy": 0.6745098039215687,
        "accuracy": 0.6739130434782609,
        "roc_auc": 0.7628045157456923,
        "brier": 0.20983417391304346,
        "log_loss": 0.6156578501429255,
        "confusion_tn_fp_fn_tp": [
          66,
          33,
          27,
          58
        ]
      },
      "split_node_counts": {
        "network": 21110
      },
      "width": 145,
      "max_features_per_node": 12
    },
    "host_29_families": {
      "metrics": {
        "samples": 184,
        "balanced_accuracy": 0.9688651218062982,
        "accuracy": 0.967391304347826,
        "roc_auc": 0.9950089126559715,
        "brier": 0.02771554347826087,
        "log_loss": 0.09545657425864651,
        "confusion_tn_fp_fn_tp": [
          94,
          5,
          1,
          84
        ]
      },
      "split_node_counts": {
        "host": 6508
      },
      "width": 145,
      "max_features_per_node": 12
    },
    "hybrid_29_plus_29": {
      "metrics": {
        "samples": 184,
        "balanced_accuracy": 0.9579322638146168,
        "accuracy": 0.9565217391304348,
        "roc_auc": 0.9907902554961379,
        "brier": 0.034091478260869564,
        "log_loss": 0.1284594873167624,
        "confusion_tn_fp_fn_tp": [
          93,
          6,
          2,
          83
        ]
      },
      "split_node_counts": {
        "host": 4115,
        "network": 2714
      },
      "width": 290,
      "max_features_per_node": 17
    }
  },
  "paired": {
    "host_only_correct": 2,
    "hybrid_only_correct": 0,
    "balanced_accuracy_delta": -0.010932857991681422,
    "mcnemar_exact_descriptive_p": 0.5,
    "caution": "Post-hoc descriptive paired test; related cases and multiplicity preclude confirmatory significance"
  },
  "disagreements": [
    {
      "sample": "1dbfe7a5e6cf95ffdf056de416e40c9b47c47ce04bc347c66767184a5ce4cca0.zip",
      "label": 1,
      "group_id": "malware_signature::GetShell",
      "host_probability": 0.622,
      "hybrid_probability": 0.386,
      "network_probability": 0.268
    },
    {
      "sample": "i386-net-tools-hostname.zip",
      "label": 0,
      "group_id": "benign_project::net-tools",
      "host_probability": 0.382,
      "hybrid_probability": 0.576,
      "network_probability": 0.538
    }
  ],
  "host_errors_network_correct": 4,
  "oracle_correct_if_either": 182,
  "oracle_note": "Label-informed upper bound, not an implementable detector or a newly fitted fusion"
}
```

## Training-Only Comparisons

BA is sample-weighted at the fixed 0.5 threshold. All variants, including losses, are retained. Equal-group metrics, seed runs, calibration, tree-count curves and block permutations are in result.json.

| Variant | Program/Hash Unit OOF BA | Family/Project OOF BA | Behavior-Cluster OOF BA |
| --- | ---: | ---: | ---: |
| host | 96.6837% | 92.9422% | 94.3878% |
| network | 65.7313% | 64.2007% | 67.2619% |
| hybrid | 94.6429% | 90.7313% | 95.0680% |
| host_mtry24 | 97.1939% | 93.4524% | not run |
| hybrid_mtry24 | 95.1531% | 91.9218% | 94.0476% |
| host_mtry_all | 96.7687% | 92.9422% | not run |
| hybrid_mtry_all | 94.6429% | 90.7313% | not run |
| hybrid_zero_network | 95.5782% | 92.9422% | not run |
| hybrid_shuffled_network | 95.0680% | 90.1361% | 93.8776% |
| host_duplicated | 96.1735% | 92.9422% | not run |
| hybrid_top5_network | 96.1735% | 93.0272% | not run |
| host_regularized | 93.5374% | 87.7551% | not run |
| hybrid_regularized | 93.6224% | 90.7313% | not run |
| host_extra_trees | 94.8980% | 88.7755% | not run |
| hybrid_extra_trees | 92.6020% | 80.6122% | not run |
| host_log | 97.1939% | 93.5374% | not run |
| hybrid_log | 94.6429% | 90.7313% | not run |
| host_activity_residual | 94.0476% | 77.0408% | not run |
| hybrid_activity_residual | 92.9422% | 75.9354% | not run |
| post_raw_counts | 96.1735% | 92.8571% | 95.5782% |
| post_raw_presence | 96.1735% | 92.7721% | not run |
| post_raw_hybrid | 95.0680% | 84.7789% | 92.0918% |
| post_raw_transitions | 95.6633% | 95.6633% | not run |
| pre_raw_counts | 50.8503% | 30.4422% | not run |
| activity_only | 79.1667% | 65.5612% | not run |
| host_activity_weighted | 94.9830% | 88.1803% | not run |
| hybrid_activity_weighted | 95.1531% | 85.7993% | not run |
| nested_logistic_fusion | 96.0884% | 93.1122% | not run |
| mean | 93.5374% | 88.2653% | 89.3707% |
| host75 | 96.0034% | 91.7517% | 94.7279% |
| or | 81.3776% | 77.7211% | 80.1020% |
| and | 81.0374% | 79.4218% | 81.5476% |
| uncertainty_gate | 96.0034% | 91.1565% | 94.2177% |

## Interpretation Boundaries

- Unit folds keep benign program/build variants together but can share families and equivalent behaviors. Family folds answer a different, unseen-group question. Behavior-cluster folds join program units, identical full-host175 vectors and identical nonempty canonical post-target sequences within declared mode. These are behavioral clusters, NOT certified malware lineages; changing folds changes the estimand.
- The hybrid has 290 candidate columns; sqrt offers17 total, approximately8.5 host on average versus12 in host-only. mtry24 approximately restores12 host candidates; all-feature controls and matching host controls distinguish this from a guaranteed causal explanation. Actual splitter search can inspect additional columns.
- Zero, shuffled and duplicated blocks isolate feature-space effects; noise rows are shuffled without labels and separately in fit/held partitions. Inference block permutation breaks correlations and can be out-of-distribution, even within broad activity/mode bins. It is sensitivity evidence, not causal attribution.
- Top-five network-family MI, residualization, weighting and feature vocabularies use only each fitting fold. Residualization uses log activity/mode/cohort and is not a causal adjustment. Activity weighting balances only both-label fitting cells; one-label cells keep weight1 and no original case is deleted.
- Raw features are newly derived archived numeric syscall-ID counts/presence/transitions, split before/after exact root target exec. They do NOT reproduce the 35-family named/fallback contract, use different widths and do not establish malicious activation. Numeric IDs are not assigned syscall names: per-event ABI is unavailable in this archive and descendants may change ABI. Loader/runtime/task/mode confounding remains.
- Nested logistic fusion uses three inner grouped folds and redoes MI inside every inner fit. Fixed mean/75%-host/OR/AND/uncertainty-gate rules are not tuned. Max/mean scores are not calibrated probabilities; Brier/log-loss are descriptive score checks.
- Seed42 is retained alongside fixed seeds7/137; no seed is selected. Tree prefixes and all mtry/regularization/ExtraTrees/log controls are sensitivity experiments, not a replacement model release. Exact paired p-values ignore related-case dependence/multiple comparisons and are descriptive, not confirmatory tests.
- Earlier offline reconstruction and 64,050 host-summary comparisons passed. Prior attribution controls demonstrated background connectivity HTTP, but general packet-to-process ownership is unverified. This experiment does not rerun those captures, repair missing events, certify binary lineage, acquire independent projects, or create untouched evaluation.

## Reproduction

Run test_hybrid_explanations.py --self-test, then --run. Each run freezes protocol/input hashes before fits and refuses output overwrite. --verify <attempt> independently recomputes every saved training OOF metric and rechecks inputs and fold separation.

All original consumed-validation limitations remain. Do not select a method or threshold from this report and claim fresh generalization or force hybrid superiority.
