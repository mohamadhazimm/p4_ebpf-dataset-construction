## Sessions

| attempt | plan | run | accepted | rejected | failed | min/session (median) | Sink packets (median) | clock drift ms (range) | flows attributed |
|---|---|---|---|---|---|---|---|---|---|
| 20261115T213142604626Z | pilot | 20 of 20 | 20 | 0 | 0 | 4.1 | 2446.0 | -91.8 to -91.1 | 100% |


## Malware behaviour: dataset run (20 s) vs session

Session class over the whole session after injection / over its first 20 s:

| dataset lab class | session class | count |
|---|---|---|
| all_answered | all_answered | 2 |
| none_answered | all_answered | 1 |
| silent | all_answered | 5 |
| some_unanswered | all_answered | 1 |

| dataset lab class | session class, first 20 s | count |
|---|---|---|
| all_answered | all_answered | 2 |
| none_answered | all_answered | 1 |
| silent | all_answered | 5 |
| some_unanswered | all_answered | 1 |

| Triage (internet) class | session class | count |
|---|---|---|
| all_answered | all_answered | 6 |
| some_unanswered | all_answered | 3 |

| sample | family | dataset packets / calls (20 s) | session flows (20 s / all) | answered | remotes | first contact s | DNS via resolver | session calls (20 s) | Spearman vs dataset row |
|---|---|---|---|---|---|---|---|---|---|
| 8124f4ac27 | CoinMiner | 26.0 / 1920.0 | 10 / 63 | 63 | 4 | 3.056 | 51 | 1921.0 | 0.931 |
| 47b6ecba4e | Kaiji | 86.0 / 7365.0 | 7 / 7 | 7 | 2 | 1.083 | 6 | 6897.0 | 0.854 |
| 0714651541 | Mirai | 977.0 / 35654.0 | 265 / 1030 | 1030 | 541 | 0.053 | 0 | 36228.0 | 0.650 |
| d328a8df79 | Ngioweb | 8.0 / 7610.0 | 4 / 14 | 14 | 1 | 0.051 | 14 | 7598.0 | 1.000 |
| 0d762c8cbb | Tsunami | 0.0 / 4735.0 | 2 / 2 | 2 | 2 | 0.05 | 1 | 9551.0 | 0.115 |
| 3e16c3bc39 | Tsunami | 0.0 / 4697.0 | 2 / 2 | 2 | 2 | 0.076 | 1 | 9687.0 | 0.113 |
| 7d22fabcc9 | Tsunami | 0.0 / 4717.0 | 1 / 1 | 1 | 1 | 0.068 | 0 | 9548.0 | 0.143 |
| 86947b00a3 | Tsunami | 0.0 / 4677.0 | 1 / 1 | 1 | 1 | 0.082 | 0 | 9477.0 | 0.143 |
| 9e28f94226 | Tsunami | 0.0 / 4737.0 | 1 / 1 | 1 | 1 | 0.273 | 0 | 9511.0 | 0.143 |

## Per-program rows, 20s (n 17, malicious 10)

Paper detectors trained on the 240 dataset rows, applied to the session rows:

| detector | BA | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.571 | 0.871 | 1.000 | 0.143 |
| network | 0.829 | 0.871 | 0.800 | 0.857 |
| concat | 0.714 | 0.900 | 1.000 | 0.429 |
| stacked | 0.643 | 0.886 | 1.000 | 0.286 |

Share flagged by kind: {"host": {"attack": 1.0, "benign": 0.8333333333333334, "malware": 1.0, "null": 1.0}, "network": {"attack": 1.0, "benign": 0.16666666666666666, "malware": 0.7777777777777778, "null": 0.0}, "concat": {"attack": 1.0, "benign": 0.5, "malware": 1.0, "null": 1.0}, "stacked": {"attack": 1.0, "benign": 0.6666666666666666, "malware": 1.0, "null": 1.0}}

Grouped CV within the session rows: 

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.539 +/- 0.139 | 0.636 | 0.420 | 0.657 |
| network | 0.606 +/- 0.121 | 0.675 | 0.670 | 0.543 |
| concat | 0.696 +/- 0.102 | 0.777 | 0.650 | 0.743 |
| stacked | 0.564 +/- 0.120 | 0.513 | 0.800 | 0.329 |

## Per-program rows, 80s (n 17, malicious 10)


Grouped CV within the session rows: 

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.506 +/- 0.090 | 0.623 | 0.340 | 0.671 |
| network | 0.471 +/- 0.094 | 0.636 | 0.400 | 0.543 |
| concat | 0.630 +/- 0.089 | 0.774 | 0.460 | 0.800 |
| stacked | 0.476 +/- 0.099 | 0.486 | 0.610 | 0.343 |

## 10-s machine windows (n 40, malicious 10)

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.603 +/- 0.047 | 0.805 | 0.270 | 0.937 |
| network | 0.653 +/- 0.084 | 0.874 | 0.340 | 0.967 |
| concat | 0.590 +/- 0.048 | 0.863 | 0.200 | 0.980 |
| stacked | 0.770 +/- 0.077 | 0.866 | 0.730 | 0.810 |
| activity baseline | 0.718 +/- 0.072 | 0.854 | 0.550 | 0.887 |

## Lab cue (a connection left unanswered)

BA 0.500, recall 0.000, specificity 1.000; flagged by kind {"attack": 0.0, "benign": 0.0, "malware": 0.0, "null": 0.0}
