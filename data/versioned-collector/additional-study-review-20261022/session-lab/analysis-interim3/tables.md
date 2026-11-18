## Sessions

| attempt | plan | run | accepted | rejected | failed | min/session (median) | Sink packets (median) | clock drift ms (range) | flows attributed |
|---|---|---|---|---|---|---|---|---|---|
| 20261115T213142604626Z | pilot | 20 of 20 | 20 | 0 | 0 | 4.1 | 2446.0 | -91.8 to -91.1 | 100% |
| 20261115T214153675625Z | main | 75 of 254 | 70 | 3 | 1 | 4.1 | 8835.5 | -183.3 to -91.0 | 100% |

- m010 attack syn-sink-40k (rejected): capture {'counters': {'captured': 128768, 'received': 128834, 'dropped': 66}, 'fetched': True, 'killed': False}
- m018 malware LockBit-4dc06ece (failed): ValueError: Guest login event timed out
- m030 attack syn-fan-40k (rejected): host-b.log: health ['HOSTMON_HEALTH,0,39761,0,0']
- m070 attack udp-fan-40k (rejected): capture {'counters': {'captured': 47792, 'received': 48626, 'dropped': 834}, 'fetched': True, 'killed': False}
- m075 none background-only (missing): ?

Programs that never started (only the waiting shell's and the launch wrapper's calls in their cgroup; left out of detection, as the dataset left out runs without an observed exec):

- m028 malware NoEscape-d7e5d1da (20261115T214153675625Z)
- m033 malware CoinMiner-9e5b93d3 (20261115T214153675625Z)
- m036 malware Tsunami-061c6641 (20261115T214153675625Z)
- m046 malware Chaos-6d29b886 (20261115T214153675625Z)

## Malware behaviour: dataset run (20 s) vs session

Session class over the whole session after injection / over its first 20 s:

| dataset lab class | session class | count |
|---|---|---|
| None | silent | 3 |
| all_answered | all_answered | 5 |
| none_answered | all_answered | 8 |
| silent | all_answered | 6 |
| silent | silent | 12 |
| some_unanswered | all_answered | 2 |

| dataset lab class | session class, first 20 s | count |
|---|---|---|
| None | silent | 3 |
| all_answered | all_answered | 5 |
| none_answered | all_answered | 8 |
| silent | all_answered | 5 |
| silent | silent | 13 |
| some_unanswered | all_answered | 2 |

| Triage (internet) class | session class | count |
|---|---|---|
| None | silent | 3 |
| all_answered | all_answered | 9 |
| none_answered | all_answered | 1 |
| silent | silent | 7 |
| some_unanswered | all_answered | 11 |
| some_unanswered | silent | 2 |
| uncertain | silent | 3 |

| sample | family | dataset packets / calls (20 s) | session flows (20 s / all) | answered | remotes | first contact s | DNS via resolver | session calls (20 s) | Spearman vs dataset row |
|---|---|---|---|---|---|---|---|---|---|
| 40c8a17d9b | Akira | 0.0 / 267.0 | 0 / 0 | 0 | 0 | None | 0 | 249.0 | 0.997 |
| 5bba035c4c | Bert | 0.0 / 5397.0 | 0 / 0 | 0 | 0 | None | 0 | 5404.0 | 0.998 |
| 750f01a5ab | BillGates | 8.0 / 1763.0 | 1 / 1 | 1 | 1 | 5.101 | 0 | 1755.0 | 0.759 |
| 2388ed7aee | BrickStorm | 0.0 / 386.0 | 0 / 0 | 0 | 0 | None | 0 | 362.0 | 0.998 |
| 80c08fc090 | CatStorm | 0.0 / 3843223.0 | 0 / 0 | 0 | 0 | None | 0 | 4256937.0 | 1.000 |
| 6d29b88651 | Chaos | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| 09bc639a01 | ChinaZ | 0.0 / 8818.0 | 0 / 0 | 0 | 0 | None | 0 | 9085.0 | 1.000 |
| 8124f4ac27 | CoinMiner | 26.0 / 1920.0 | 10 / 63 | 63 | 4 | 3.056 | 51 | 1921.0 | 0.931 |
| 9e5b93d309 | CoinMiner | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| 035a6840a1 | DDoSAgent | 0.0 / 1636.0 | 0 / 0 | 0 | 0 | None | 0 | 1651.0 | 0.999 |
| f0b98f9570 | DeskRAT | 0.0 / 22880.0 | 0 / 20 | 20 | 2 | 24.553 | 15 | 49178.0 | 0.993 |
| 990628a240 | Dofloo | 10.0 / 2363.0 | 1 / 2 | 2 | 1 | 0.071 | 0 | 2566.0 | 0.739 |
| 00472840f6 | Gafgyt | 9.0 / 201.0 | 1 / 1 | 1 | 1 | 0.054 | 0 | 285.0 | 0.643 |
| 690711e086 | GetShell | 0.0 / 194.0 | 0 / 0 | 0 | 0 | None | 0 | 182.0 | 0.997 |
| 86d0447445 | INC | 0.0 / 278.0 | 0 / 0 | 0 | 0 | None | 0 | 266.0 | 0.997 |
| 0088509f1a | Kaiji | 15.0 / 4433.0 | 4 / 4 | 4 | 2 | 0.037 | 3 | 5113.0 | 0.939 |
| 47b6ecba4e | Kaiji | 86.0 / 7365.0 | 7 / 7 | 7 | 2 | 1.083 | 6 | 6897.0 | 0.854 |
| 80b4d47bfb | Kaiten | 80.0 / 719.0 | 2 / 2 | 2 | 2 | 0.048 | 1 | 276.0 | 0.833 |
| 6cc3fc0284 | Katana | 12.0 / 10473.0 | 2 / 2 | 2 | 2 | 0.053 | 1 | 8889.0 | 0.924 |
| 0007edc2bd | Mirai | 0.0 / 187.0 | 0 / 0 | 0 | 0 | None | 0 | 175.0 | 0.997 |
| 0714651541 | Mirai | 977.0 / 35654.0 | 265 / 1030 | 1030 | 541 | 0.053 | 0 | 36228.0 | 0.650 |
| d328a8df79 | Ngioweb | 8.0 / 7610.0 | 4 / 14 | 14 | 1 | 0.051 | 14 | 7598.0 | 1.000 |
| fc43bc3a09 | Ngioweb | 8.0 / 7612.0 | 4 / 18 | 18 | 1 | 0.053 | 18 | 7601.0 | 0.999 |
| 0859497eea | Nitrogen | 0.0 / 197.0 | 0 / 0 | 0 | 0 | None | 0 | 185.0 | 0.997 |
| d7e5d1da2d | NoEscape | 0.0 / 178.0 | 0 / 0 | 0 | 0 | None | 0 | 166.0 | 0.997 |
| 765b0ad71a | Prometei | 8.0 / 3847.0 | 1 / 11 | 11 | 4 | 10.773 | 0 | 4146.0 | 0.742 |
| 2755e1ec1e | PromptLock | 9.0 / 442.0 | 1 / 1 | 1 | 1 | 0.018 | 0 | 432.0 | 0.762 |
| 67cdee8253 | Qilin | 0.0 / 234.0 | 0 / 0 | 0 | 0 | None | 0 | 222.0 | 0.996 |
| 6c034ff9b5 | RapperBot | 21.0 / 6521.0 | 1 / 1 | 1 | 1 | 0.033 | 0 | 6400.0 | 0.735 |
| 061c664196 | Tsunami | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| 0d762c8cbb | Tsunami | 0.0 / 4735.0 | 2 / 2 | 2 | 2 | 0.05 | 1 | 9551.0 | 0.115 |
| 3e16c3bc39 | Tsunami | 0.0 / 4697.0 | 2 / 2 | 2 | 2 | 0.076 | 1 | 9687.0 | 0.113 |
| 7d22fabcc9 | Tsunami | 0.0 / 4717.0 | 1 / 1 | 1 | 1 | 0.068 | 0 | 9548.0 | 0.143 |
| 86947b00a3 | Tsunami | 0.0 / 4677.0 | 1 / 1 | 1 | 1 | 0.082 | 0 | 9477.0 | 0.143 |
| 9e28f94226 | Tsunami | 0.0 / 4737.0 | 1 / 1 | 1 | 1 | 0.273 | 0 | 9511.0 | 0.143 |
| 47c0af3e02 | XorDDoS | 10.0 / 4619.0 | 9 / 34 | 34 | 3 | 0.037 | 0 | 4898.0 | 0.792 |

## Benign tasks: session (first 20 s of the program) vs dataset row

Median Spearman over 235 columns: 0.997 (28 tasks)


## Per-program rows, 20s (n 72, malicious 34)

Paper detectors trained on the 240 dataset rows, applied to the session rows:

| detector | BA | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.748 | 0.893 | 0.971 | 0.526 |
| network | 0.722 | 0.738 | 0.471 | 0.974 |
| concat | 0.789 | 0.925 | 1.000 | 0.579 |
| stacked | 0.773 | 0.917 | 0.941 | 0.605 |

Share flagged by kind: {"host": {"attack": 0.5, "benign": 0.4117647058823529, "malware": 1.0, "null": 1.0}, "network": {"attack": 1.0, "benign": 0.029411764705882353, "malware": 0.4375, "null": 0.0}, "concat": {"attack": 1.0, "benign": 0.35294117647058826, "malware": 1.0, "null": 1.0}, "stacked": {"attack": 1.0, "benign": 0.35294117647058826, "malware": 0.9375, "null": 0.75}}

Start-up signature columns (dataset rows vs session rows, min / median / max):

| column | dataset | sessions |
|---|---|---|
| host_max_run_length_max__max | 54 / 54 / 52866 | 12 / 19 / 32774 |
| host_first50_unique_mean__max | 1.31223 / 5 / 23 | 1.30648 / 21 / 22.3333 |
| host_first100_unique_mean__max | 6 / 15 / 27 | 9.5 / 22 / 24.3333 |

Same transfer without the start-up-dominated host signals (host_max_run_length_mean, host_max_run_length_max, host_first50_unique_mean, host_first50_unique_max, host_first100_unique_mean, host_first100_unique_max; post hoc):

| detector | BA | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.795 | 0.909 | 0.853 | 0.737 |
| network | 0.722 | 0.738 | 0.471 | 0.974 |
| concat | 0.839 | 0.933 | 0.941 | 0.737 |
| stacked | 0.844 | 0.930 | 0.794 | 0.895 |

Share flagged by kind: {"host": {"attack": 0.5, "benign": 0.2647058823529412, "malware": 0.875, "null": 0.25}, "network": {"attack": 1.0, "benign": 0.029411764705882353, "malware": 0.4375, "null": 0.0}, "concat": {"attack": 1.0, "benign": 0.20588235294117646, "malware": 0.9375, "null": 0.75}, "stacked": {"attack": 1.0, "benign": 0.11764705882352941, "malware": 0.78125, "null": 0.0}}

Grouped CV within the session rows (families / projects held out): 

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.855 +/- 0.019 | 0.850 | 0.765 | 0.945 | 0.732 / 0.779 |
| network | 0.749 +/- 0.015 | 0.719 | 0.612 | 0.887 | 0.453 / 0.588 |
| concat | 0.840 +/- 0.028 | 0.887 | 0.753 | 0.926 | 0.671 / 0.776 |
| stacked | 0.820 +/- 0.028 | 0.863 | 0.735 | 0.905 | 0.668 / 0.744 |
| baseline: activity | 0.737 +/- 0.027 | 0.768 | 0.697 | 0.776 | 0.238 / 0.415 |
| baseline: lifetime | 0.660 +/- 0.061 | 0.620 | 0.509 | 0.811 | 0.288 / 0.368 |
| baseline: injection_time | 0.648 +/- 0.023 | 0.714 | 0.603 | 0.692 | 0.076 / 0.371 |
| baseline: batch | 0.501 +/- 0.048 | 0.494 | 0.253 | 0.750 | 0.003 / 0.024 |
| baseline: mode | 0.530 +/- 0.044 | 0.507 | 0.394 | 0.666 | 0.000 / 0.068 |

One-feature baselines on random noise (20 draws, same folds): BA mean 0.460, 95th percentile 0.552, max 0.559

network_minus_host (BA, per fold assignment): -0.105 +/- 0.017, positive in 0 of 10

concat_minus_host (BA, per fold assignment): -0.015 +/- 0.025, positive in 3 of 10

stacked_minus_host (BA, per fold assignment): -0.034 +/- 0.018, positive in 0 of 10

Seen families (stratified folds, rows of one family in training and test):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.827 +/- 0.035 | 0.849 | 0.768 | 0.887 |
| network | 0.731 +/- 0.024 | 0.711 | 0.609 | 0.853 |
| concat | 0.801 +/- 0.046 | 0.868 | 0.750 | 0.853 |
| stacked | 0.822 +/- 0.038 | 0.864 | 0.774 | 0.871 |

Share flagged per group (mean over fold assignments; malicious groups: recall):

| group | label | rows | host | network | concat | stacked |
|---|---|---|---|---|---|---|
| attack::syn-sink-40k | 1 | 1 | 0% | 100% | 10% | 0% |
| attack::udp-direct-40k | 1 | 1 | 0% | 100% | 0% | 0% |
| family::Akira | 1 | 1 | 80% | 0% | 60% | 10% |
| family::Bert | 1 | 1 | 100% | 0% | 40% | 70% |
| family::BillGates | 1 | 1 | 100% | 90% | 100% | 100% |
| family::BrickStorm | 1 | 1 | 0% | 0% | 0% | 0% |
| family::CatStorm | 1 | 1 | 100% | 0% | 100% | 100% |
| family::ChinaZ | 1 | 1 | 100% | 0% | 80% | 90% |
| family::CoinMiner | 1 | 1 | 100% | 100% | 100% | 100% |
| family::DDoSAgent | 1 | 1 | 100% | 0% | 70% | 80% |
| family::DeskRAT | 1 | 1 | 100% | 0% | 100% | 100% |
| family::Dofloo | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Gafgyt | 1 | 1 | 100% | 90% | 100% | 100% |
| family::GetShell | 1 | 1 | 70% | 0% | 60% | 30% |
| family::INC | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Kaiji | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Kaiten | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Katana | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Mirai | 1 | 2 | 75% | 45% | 80% | 65% |
| family::Ngioweb | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Nitrogen | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Prometei | 1 | 1 | 100% | 10% | 100% | 100% |
| family::PromptLock | 1 | 1 | 0% | 100% | 80% | 90% |
| family::Qilin | 1 | 1 | 0% | 0% | 0% | 0% |
| family::RapperBot | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Tsunami | 1 | 5 | 100% | 100% | 100% | 100% |
| family::XorDDoS | 1 | 1 | 100% | 100% | 100% | 100% |
| benign::archive-docs | 0 | 1 | 100% | 0% | 100% | 100% |
| benign::browse-public | 0 | 1 | 0% | 30% | 0% | 0% |
| benign::checkin-public | 0 | 1 | 0% | 40% | 0% | 0% |
| benign::dns-poll | 0 | 1 | 0% | 100% | 60% | 70% |
| benign::download-burst | 0 | 1 | 0% | 0% | 0% | 0% |
| benign::file-search | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_amd64_dynamic-start | 0 | 1 | 40% | 0% | 30% | 30% |
| null::null-native_amd64_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_i386_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-true | 0 | 1 | 0% | 0% | 0% | 0% |
| project::brotli | 0 | 1 | 10% | 0% | 10% | 10% |
| project::bzip2 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::coreutils | 0 | 2 | 0% | 0% | 0% | 0% |
| project::cpio | 0 | 1 | 0% | 0% | 0% | 0% |
| project::curl | 0 | 1 | 0% | 90% | 10% | 10% |
| project::diffutils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::expat | 0 | 1 | 10% | 0% | 60% | 10% |
| project::git | 0 | 1 | 0% | 0% | 0% | 0% |
| project::gzip | 0 | 2 | 0% | 0% | 0% | 0% |
| project::inetutils | 0 | 1 | 0% | 100% | 0% | 60% |
| project::jq | 0 | 1 | 0% | 0% | 0% | 0% |
| project::libzstd | 0 | 1 | 0% | 0% | 0% | 0% |
| project::lz4 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::m4 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::ncompress | 0 | 2 | 0% | 0% | 0% | 0% |
| project::openssl | 0 | 1 | 0% | 0% | 0% | 0% |
| project::rsync | 0 | 1 | 40% | 0% | 0% | 10% |
| project::sqlite3 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::tar | 0 | 1 | 0% | 0% | 0% | 0% |
| project::unzip | 0 | 1 | 0% | 0% | 0% | 0% |
| project::wget | 0 | 1 | 10% | 70% | 10% | 60% |
| project::xxhash | 0 | 2 | 0% | 0% | 0% | 0% |
| project::xz-utils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::zip | 0 | 1 | 0% | 0% | 0% | 0% |

## Per-program rows, 80s (n 72, malicious 34)


Grouped CV within the session rows (families / projects held out): 

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.866 +/- 0.019 | 0.854 | 0.782 | 0.950 | 0.756 / 0.797 |
| network | 0.734 +/- 0.021 | 0.733 | 0.588 | 0.879 | 0.503 / 0.579 |
| concat | 0.830 +/- 0.024 | 0.889 | 0.744 | 0.916 | 0.644 / 0.756 |
| stacked | 0.824 +/- 0.025 | 0.867 | 0.732 | 0.916 | 0.609 / 0.753 |
| baseline: activity | 0.655 +/- 0.027 | 0.708 | 0.588 | 0.721 | 0.229 / 0.371 |
| baseline: lifetime | 0.702 +/- 0.019 | 0.657 | 0.588 | 0.816 | 0.294 / 0.344 |
| baseline: injection_time | 0.648 +/- 0.023 | 0.714 | 0.603 | 0.692 | 0.076 / 0.371 |
| baseline: batch | 0.501 +/- 0.048 | 0.494 | 0.253 | 0.750 | 0.003 / 0.024 |
| baseline: mode | 0.530 +/- 0.044 | 0.507 | 0.394 | 0.666 | 0.000 / 0.068 |

One-feature baselines on random noise (20 draws, same folds): BA mean 0.460, 95th percentile 0.552, max 0.559

network_minus_host (BA, per fold assignment): -0.133 +/- 0.021, positive in 0 of 10

concat_minus_host (BA, per fold assignment): -0.036 +/- 0.017, positive in 0 of 10

stacked_minus_host (BA, per fold assignment): -0.042 +/- 0.026, positive in 0 of 10

Seen families (stratified folds, rows of one family in training and test):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.837 +/- 0.027 | 0.852 | 0.771 | 0.903 |
| network | 0.736 +/- 0.025 | 0.726 | 0.615 | 0.858 |
| concat | 0.814 +/- 0.031 | 0.876 | 0.750 | 0.879 |
| stacked | 0.832 +/- 0.022 | 0.868 | 0.756 | 0.908 |

Share flagged per group (mean over fold assignments; malicious groups: recall):

| group | label | rows | host | network | concat | stacked |
|---|---|---|---|---|---|---|
| attack::syn-sink-40k | 1 | 1 | 0% | 100% | 20% | 0% |
| attack::udp-direct-40k | 1 | 1 | 0% | 100% | 0% | 0% |
| family::Akira | 1 | 1 | 50% | 0% | 50% | 10% |
| family::Bert | 1 | 1 | 90% | 0% | 20% | 70% |
| family::BillGates | 1 | 1 | 100% | 100% | 100% | 100% |
| family::BrickStorm | 1 | 1 | 0% | 0% | 0% | 0% |
| family::CatStorm | 1 | 1 | 100% | 0% | 100% | 100% |
| family::ChinaZ | 1 | 1 | 100% | 0% | 80% | 90% |
| family::CoinMiner | 1 | 1 | 100% | 100% | 100% | 100% |
| family::DDoSAgent | 1 | 1 | 100% | 0% | 40% | 60% |
| family::DeskRAT | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Dofloo | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Gafgyt | 1 | 1 | 100% | 70% | 100% | 100% |
| family::GetShell | 1 | 1 | 80% | 0% | 60% | 30% |
| family::INC | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Kaiji | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Kaiten | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Katana | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Mirai | 1 | 2 | 85% | 50% | 80% | 65% |
| family::Ngioweb | 1 | 2 | 100% | 20% | 100% | 100% |
| family::Nitrogen | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Prometei | 1 | 1 | 100% | 0% | 100% | 100% |
| family::PromptLock | 1 | 1 | 70% | 100% | 100% | 100% |
| family::Qilin | 1 | 1 | 0% | 0% | 0% | 0% |
| family::RapperBot | 1 | 1 | 100% | 90% | 100% | 100% |
| family::Tsunami | 1 | 5 | 100% | 100% | 100% | 100% |
| family::XorDDoS | 1 | 1 | 100% | 100% | 100% | 100% |
| benign::archive-docs | 0 | 1 | 100% | 0% | 100% | 100% |
| benign::browse-public | 0 | 1 | 0% | 20% | 0% | 0% |
| benign::checkin-public | 0 | 1 | 0% | 80% | 60% | 40% |
| benign::dns-poll | 0 | 1 | 0% | 100% | 80% | 90% |
| benign::download-burst | 0 | 1 | 0% | 0% | 0% | 0% |
| benign::file-search | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_amd64_dynamic-start | 0 | 1 | 40% | 0% | 40% | 20% |
| null::null-native_amd64_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_i386_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-true | 0 | 1 | 0% | 0% | 0% | 0% |
| project::brotli | 0 | 1 | 20% | 0% | 0% | 10% |
| project::bzip2 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::coreutils | 0 | 2 | 0% | 0% | 0% | 0% |
| project::cpio | 0 | 1 | 0% | 0% | 0% | 0% |
| project::curl | 0 | 1 | 0% | 70% | 0% | 0% |
| project::diffutils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::expat | 0 | 1 | 30% | 0% | 40% | 10% |
| project::git | 0 | 1 | 0% | 0% | 0% | 0% |
| project::gzip | 0 | 2 | 0% | 0% | 0% | 0% |
| project::inetutils | 0 | 1 | 0% | 100% | 0% | 30% |
| project::jq | 0 | 1 | 0% | 0% | 0% | 0% |
| project::libzstd | 0 | 1 | 0% | 0% | 0% | 0% |
| project::lz4 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::m4 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::ncompress | 0 | 2 | 0% | 0% | 0% | 0% |
| project::openssl | 0 | 1 | 0% | 30% | 0% | 0% |
| project::rsync | 0 | 1 | 0% | 0% | 0% | 0% |
| project::sqlite3 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::tar | 0 | 1 | 0% | 0% | 0% | 0% |
| project::unzip | 0 | 1 | 0% | 0% | 0% | 0% |
| project::wget | 0 | 1 | 0% | 60% | 0% | 20% |
| project::xxhash | 0 | 2 | 0% | 0% | 0% | 0% |
| project::xz-utils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::zip | 0 | 1 | 0% | 0% | 0% | 0% |

## Sensitivity: per-program rows, 20 s, including the programs that never started (n 76, malicious 38)

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.854 +/- 0.014 | 0.858 | 0.792 | 0.916 |
| network | 0.711 +/- 0.012 | 0.695 | 0.539 | 0.882 |
| concat | 0.832 +/- 0.030 | 0.883 | 0.774 | 0.889 |
| stacked | 0.847 +/- 0.026 | 0.871 | 0.797 | 0.897 |

## 10-s machine windows (n 164, malicious 34)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.571 +/- 0.012 | 0.830 | 0.176 | 0.965 | 0.241 / 0.329 |
| network | 0.561 +/- 0.035 | 0.762 | 0.126 | 0.995 | 0.238 / 0.365 |
| concat | 0.550 +/- 0.014 | 0.860 | 0.109 | 0.991 | 0.306 / 0.450 |
| stacked | 0.768 +/- 0.045 | 0.857 | 0.768 | 0.769 | 0.282 / 0.462 |
| activity baseline | 0.657 +/- 0.033 | 0.758 | 0.450 | 0.865 | 0.262 / 0.382 |
| position baseline | 0.620 +/- 0.028 | 0.728 | 0.435 | 0.805 | 0.274 / 0.329 |

One-feature baselines on random noise (10 draws): BA mean 0.491, 95th percentile 0.550, max 0.559

network_minus_host (BA, per fold assignment): -0.010 +/- 0.032, positive in 2 of 10

concat_minus_host (BA, per fold assignment): -0.021 +/- 0.020, positive in 1 of 10

stacked_minus_host (BA, per fold assignment): +0.198 +/- 0.047, positive in 10 of 10

Seen families (stratified folds):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.631 +/- 0.026 | 0.857 | 0.309 | 0.952 |
| network | 0.607 +/- 0.029 | 0.747 | 0.218 | 0.997 |
| concat | 0.609 +/- 0.028 | 0.881 | 0.226 | 0.992 |
| stacked | 0.769 +/- 0.030 | 0.871 | 0.762 | 0.777 |

## 30-s machine windows (n 164, malicious 34)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.633 +/- 0.013 | 0.823 | 0.288 | 0.977 | 0.353 / 0.444 |
| network | 0.540 +/- 0.022 | 0.688 | 0.088 | 0.992 | 0.185 / 0.276 |
| concat | 0.611 +/- 0.017 | 0.823 | 0.235 | 0.988 | 0.371 / 0.485 |
| stacked | 0.725 +/- 0.039 | 0.828 | 0.638 | 0.811 | 0.379 / 0.476 |
| activity baseline | 0.546 +/- 0.034 | 0.619 | 0.309 | 0.784 | 0.115 / 0.165 |
| position baseline | 0.689 +/- 0.027 | 0.779 | 0.532 | 0.846 | 0.347 / 0.459 |

One-feature baselines on random noise (10 draws): BA mean 0.491, 95th percentile 0.550, max 0.559

network_minus_host (BA, per fold assignment): -0.093 +/- 0.028, positive in 0 of 10

concat_minus_host (BA, per fold assignment): -0.021 +/- 0.019, positive in 2 of 10

stacked_minus_host (BA, per fold assignment): +0.092 +/- 0.049, positive in 10 of 10

Seen families (stratified folds):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.702 +/- 0.011 | 0.857 | 0.429 | 0.974 |
| network | 0.586 +/- 0.028 | 0.740 | 0.182 | 0.990 |
| concat | 0.688 +/- 0.029 | 0.873 | 0.391 | 0.984 |
| stacked | 0.778 +/- 0.016 | 0.866 | 0.718 | 0.838 |

## Lab cue (a connection left unanswered)

BA 0.515, recall 0.029, specificity 1.000; flagged by kind {"attack": 0.5, "benign": 0.0, "malware": 0.0, "null": 0.0}
