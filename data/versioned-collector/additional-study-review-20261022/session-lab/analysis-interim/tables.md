## Sessions

| attempt | plan | run | accepted | rejected | failed | min/session (median) | Sink packets (median) | clock drift ms (range) | flows attributed |
|---|---|---|---|---|---|---|---|---|---|
| 20261115T213142604626Z | pilot | 20 of 20 | 20 | 0 | 0 | 4.1 | 2446.0 | -91.8 to -91.1 | 100% |
| 20261115T214153675625Z | main | 44 of 254 | 40 | 2 | 1 | 4.1 | 8851 | -183.3 to -91.0 | 100% |

- m010 attack syn-sink-40k (rejected): capture {'counters': {'captured': 128768, 'received': 128834, 'dropped': 66}, 'fetched': True, 'killed': False}
- m018 malware LockBit-4dc06ece (failed): ValueError: Guest login event timed out
- m030 attack syn-fan-40k (rejected): host-b.log: health ['HOSTMON_HEALTH,0,39761,0,0']
- m044 benign rsync-rsync-32353886 (missing): ?

## Malware behaviour: dataset run (20 s) vs session

Session class over the whole session after injection / over its first 20 s:

| dataset lab class | session class | count |
|---|---|---|
| None | silent | 2 |
| all_answered | all_answered | 4 |
| none_answered | all_answered | 5 |
| silent | all_answered | 6 |
| silent | silent | 7 |
| some_unanswered | all_answered | 2 |

| dataset lab class | session class, first 20 s | count |
|---|---|---|
| None | silent | 2 |
| all_answered | all_answered | 4 |
| none_answered | all_answered | 5 |
| silent | all_answered | 5 |
| silent | silent | 8 |
| some_unanswered | all_answered | 2 |

| Triage (internet) class | session class | count |
|---|---|---|
| None | silent | 2 |
| all_answered | all_answered | 6 |
| none_answered | all_answered | 1 |
| silent | silent | 3 |
| some_unanswered | all_answered | 10 |
| some_unanswered | silent | 1 |
| uncertain | silent | 3 |

| sample | family | dataset packets / calls (20 s) | session flows (20 s / all) | answered | remotes | first contact s | DNS via resolver | session calls (20 s) | Spearman vs dataset row |
|---|---|---|---|---|---|---|---|---|---|
| 5bba035c4c | Bert | 0.0 / 5397.0 | 0 / 0 | 0 | 0 | None | 0 | 5404.0 | 0.998 |
| 750f01a5ab | BillGates | 8.0 / 1763.0 | 1 / 1 | 1 | 1 | 5.101 | 0 | 1755.0 | 0.759 |
| 2388ed7aee | BrickStorm | 0.0 / 386.0 | 0 / 0 | 0 | 0 | None | 0 | 362.0 | 0.998 |
| 09bc639a01 | ChinaZ | 0.0 / 8818.0 | 0 / 0 | 0 | 0 | None | 0 | 9085.0 | 1.000 |
| 8124f4ac27 | CoinMiner | 26.0 / 1920.0 | 10 / 63 | 63 | 4 | 3.056 | 51 | 1921.0 | 0.931 |
| 9e5b93d309 | CoinMiner | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| f0b98f9570 | DeskRAT | 0.0 / 22880.0 | 0 / 20 | 20 | 2 | 24.553 | 15 | 49178.0 | 0.993 |
| 00472840f6 | Gafgyt | 9.0 / 201.0 | 1 / 1 | 1 | 1 | 0.054 | 0 | 285.0 | 0.643 |
| 0088509f1a | Kaiji | 15.0 / 4433.0 | 4 / 4 | 4 | 2 | 0.037 | 3 | 5113.0 | 0.939 |
| 47b6ecba4e | Kaiji | 86.0 / 7365.0 | 7 / 7 | 7 | 2 | 1.083 | 6 | 6897.0 | 0.854 |
| 80b4d47bfb | Kaiten | 80.0 / 719.0 | 2 / 2 | 2 | 2 | 0.048 | 1 | 276.0 | 0.833 |
| 6cc3fc0284 | Katana | 12.0 / 10473.0 | 2 / 2 | 2 | 2 | 0.053 | 1 | 8889.0 | 0.924 |
| 0007edc2bd | Mirai | 0.0 / 187.0 | 0 / 0 | 0 | 0 | None | 0 | 175.0 | 0.997 |
| 0714651541 | Mirai | 977.0 / 35654.0 | 265 / 1030 | 1030 | 541 | 0.053 | 0 | 36228.0 | 0.650 |
| d328a8df79 | Ngioweb | 8.0 / 7610.0 | 4 / 14 | 14 | 1 | 0.051 | 14 | 7598.0 | 1.000 |
| 0859497eea | Nitrogen | 0.0 / 197.0 | 0 / 0 | 0 | 0 | None | 0 | 185.0 | 0.997 |
| d7e5d1da2d | NoEscape | 0.0 / 178.0 | 0 / 0 | 0 | 0 | None | 0 | 166.0 | 0.997 |
| 2755e1ec1e | PromptLock | 9.0 / 442.0 | 1 / 1 | 1 | 1 | 0.018 | 0 | 432.0 | 0.762 |
| 67cdee8253 | Qilin | 0.0 / 234.0 | 0 / 0 | 0 | 0 | None | 0 | 222.0 | 0.996 |
| 6c034ff9b5 | RapperBot | 21.0 / 6521.0 | 1 / 1 | 1 | 1 | 0.033 | 0 | 6400.0 | 0.735 |
| 061c664196 | Tsunami | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| 0d762c8cbb | Tsunami | 0.0 / 4735.0 | 2 / 2 | 2 | 2 | 0.05 | 1 | 9551.0 | 0.115 |
| 3e16c3bc39 | Tsunami | 0.0 / 4697.0 | 2 / 2 | 2 | 2 | 0.076 | 1 | 9687.0 | 0.113 |
| 7d22fabcc9 | Tsunami | 0.0 / 4717.0 | 1 / 1 | 1 | 1 | 0.068 | 0 | 9548.0 | 0.143 |
| 86947b00a3 | Tsunami | 0.0 / 4677.0 | 1 / 1 | 1 | 1 | 0.082 | 0 | 9477.0 | 0.143 |
| 9e28f94226 | Tsunami | 0.0 / 4737.0 | 1 / 1 | 1 | 1 | 0.273 | 0 | 9511.0 | 0.143 |

## Benign tasks: session (first 20 s of the program) vs dataset row

Median Spearman over 235 columns: 0.996 (17 tasks)


## Per-program rows, 20s (n 53, malicious 27)

Paper detectors trained on the 240 dataset rows, applied to the session rows:

| detector | BA | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.769 | 0.875 | 1.000 | 0.538 |
| network | 0.703 | 0.758 | 0.444 | 0.962 |
| concat | 0.808 | 0.915 | 1.000 | 0.615 |
| stacked | 0.789 | 0.903 | 0.963 | 0.615 |

Share flagged by kind: {"host": {"attack": 1.0, "benign": 0.391304347826087, "malware": 1.0, "null": 1.0}, "network": {"attack": 1.0, "benign": 0.043478260869565216, "malware": 0.4230769230769231, "null": 0.0}, "concat": {"attack": 1.0, "benign": 0.30434782608695654, "malware": 1.0, "null": 1.0}, "stacked": {"attack": 1.0, "benign": 0.30434782608695654, "malware": 0.9615384615384616, "null": 1.0}}

Grouped CV within the session rows: 

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.848 +/- 0.026 | 0.832 | 0.815 | 0.881 | 0.715 / 0.741 |
| network | 0.731 +/- 0.027 | 0.740 | 0.604 | 0.858 | 0.526 / 0.585 |
| concat | 0.839 +/- 0.029 | 0.846 | 0.796 | 0.881 | 0.630 / 0.715 |
| stacked | 0.853 +/- 0.028 | 0.852 | 0.822 | 0.885 | 0.678 / 0.756 |

## Per-program rows, 80s (n 53, malicious 27)


Grouped CV within the session rows: 

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.870 +/- 0.025 | 0.828 | 0.848 | 0.892 | 0.689 / 0.733 |
| network | 0.741 +/- 0.023 | 0.751 | 0.593 | 0.888 | 0.567 / 0.581 |
| concat | 0.844 +/- 0.026 | 0.862 | 0.815 | 0.873 | 0.681 / 0.763 |
| stacked | 0.846 +/- 0.026 | 0.856 | 0.807 | 0.885 | 0.678 / 0.737 |

## 10-s machine windows (n 120, malicious 27)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.560 +/- 0.034 | 0.821 | 0.167 | 0.953 | 0.163 / 0.259 |
| network | 0.550 +/- 0.033 | 0.669 | 0.111 | 0.989 | 0.215 / 0.278 |
| concat | 0.530 +/- 0.018 | 0.836 | 0.078 | 0.983 | 0.174 / 0.393 |
| stacked | 0.759 +/- 0.051 | 0.826 | 0.767 | 0.751 | 0.122 / 0.296 |
| activity baseline | 0.629 +/- 0.038 | 0.677 | 0.422 | 0.837 | 0.230 / 0.322 |

## 30-s machine windows (n 120, malicious 27)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.642 +/- 0.027 | 0.837 | 0.296 | 0.987 | 0.437 / 0.552 |
| network | 0.547 +/- 0.014 | 0.715 | 0.107 | 0.986 | 0.219 / 0.315 |
| concat | 0.568 +/- 0.020 | 0.821 | 0.141 | 0.996 | 0.359 / 0.493 |
| stacked | 0.736 +/- 0.036 | 0.837 | 0.711 | 0.760 | 0.500 / 0.570 |
| activity baseline | 0.523 +/- 0.053 | 0.551 | 0.237 | 0.810 | 0.044 / 0.089 |

## Lab cue (a connection left unanswered)

BA 0.500, recall 0.000, specificity 1.000; flagged by kind {"attack": 0.0, "benign": 0.0, "malware": 0.0, "null": 0.0}
