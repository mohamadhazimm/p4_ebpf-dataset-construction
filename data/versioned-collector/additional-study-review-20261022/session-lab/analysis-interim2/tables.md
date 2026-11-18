## Sessions

| attempt | plan | run | accepted | rejected | failed | min/session (median) | Sink packets (median) | clock drift ms (range) | flows attributed |
|---|---|---|---|---|---|---|---|---|---|
| 20261115T213142604626Z | pilot | 20 of 20 | 20 | 0 | 0 | 4.1 | 2446.0 | -91.8 to -91.1 | 100% |
| 20261115T214153675625Z | main | 70 of 254 | 66 | 2 | 1 | 4.1 | 8820 | -183.3 to -91.0 | 100% |

- m010 attack syn-sink-40k (rejected): capture {'counters': {'captured': 128768, 'received': 128834, 'dropped': 66}, 'fetched': True, 'killed': False}
- m018 malware LockBit-4dc06ece (failed): ValueError: Guest login event timed out
- m030 attack syn-fan-40k (rejected): host-b.log: health ['HOSTMON_HEALTH,0,39761,0,0']
- m070 attack udp-fan-40k (missing): ?

## Malware behaviour: dataset run (20 s) vs session

Session class over the whole session after injection / over its first 20 s:

| dataset lab class | session class | count |
|---|---|---|
| None | silent | 3 |
| all_answered | all_answered | 5 |
| none_answered | all_answered | 7 |
| silent | all_answered | 6 |
| silent | silent | 12 |
| some_unanswered | all_answered | 2 |

| dataset lab class | session class, first 20 s | count |
|---|---|---|
| None | silent | 3 |
| all_answered | all_answered | 5 |
| none_answered | all_answered | 7 |
| silent | all_answered | 5 |
| silent | silent | 13 |
| some_unanswered | all_answered | 2 |

| Triage (internet) class | session class | count |
|---|---|---|
| None | silent | 3 |
| all_answered | all_answered | 9 |
| none_answered | all_answered | 1 |
| silent | silent | 7 |
| some_unanswered | all_answered | 10 |
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

## Benign tasks: session (first 20 s of the program) vs dataset row

Median Spearman over 235 columns: 0.998 (27 tasks)


## Per-program rows, 20s (n 74, malicious 37)

Paper detectors trained on the 240 dataset rows, applied to the session rows:

| detector | BA | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.757 | 0.879 | 0.973 | 0.541 |
| network | 0.689 | 0.715 | 0.405 | 0.973 |
| concat | 0.797 | 0.922 | 1.000 | 0.595 |
| stacked | 0.784 | 0.909 | 0.946 | 0.622 |

Share flagged by kind: {"host": {"attack": 0.5, "benign": 0.3939393939393939, "malware": 1.0, "null": 1.0}, "network": {"attack": 1.0, "benign": 0.030303030303030304, "malware": 0.37142857142857144, "null": 0.0}, "concat": {"attack": 1.0, "benign": 0.3333333333333333, "malware": 1.0, "null": 1.0}, "stacked": {"attack": 1.0, "benign": 0.3333333333333333, "malware": 0.9428571428571428, "null": 0.75}}

Start-up signature columns (dataset rows vs session rows, min / median / max):

| column | dataset | sessions |
|---|---|---|
| host_max_run_length_max__max | 54 / 54 / 52866 | 12 / 17 / 32774 |
| host_first50_unique_mean__max | 1.31223 / 5 / 23 | 1.30648 / 21 / 22.3333 |
| host_first100_unique_mean__max | 6 / 15 / 27 | 9.5 / 22 / 24.3333 |

Same transfer without the start-up-dominated host signals (host_max_run_length_mean, host_max_run_length_max, host_first50_unique_mean, host_first50_unique_max, host_first100_unique_mean, host_first100_unique_max; post hoc):

| detector | BA | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.797 | 0.896 | 0.865 | 0.730 |
| network | 0.689 | 0.715 | 0.405 | 0.973 |
| concat | 0.851 | 0.934 | 0.946 | 0.757 |
| stacked | 0.851 | 0.923 | 0.811 | 0.892 |

Share flagged by kind: {"host": {"attack": 0.5, "benign": 0.2727272727272727, "malware": 0.8857142857142857, "null": 0.25}, "network": {"attack": 1.0, "benign": 0.030303030303030304, "malware": 0.37142857142857144, "null": 0.0}, "concat": {"attack": 1.0, "benign": 0.18181818181818182, "malware": 0.9428571428571428, "null": 0.75}, "stacked": {"attack": 1.0, "benign": 0.12121212121212122, "malware": 0.8, "null": 0.0}}

Grouped CV within the session rows (families / projects held out): 

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.842 +/- 0.037 | 0.862 | 0.778 | 0.905 | 0.714 / 0.781 |
| network | 0.714 +/- 0.012 | 0.681 | 0.541 | 0.886 | 0.349 / 0.503 |
| concat | 0.836 +/- 0.030 | 0.890 | 0.786 | 0.886 | 0.684 / 0.770 |
| stacked | 0.853 +/- 0.022 | 0.876 | 0.805 | 0.900 | 0.700 / 0.800 |
| baseline: activity | 0.753 +/- 0.018 | 0.791 | 0.738 | 0.768 | 0.351 / 0.511 |
| baseline: lifetime | 0.609 +/- 0.047 | 0.577 | 0.403 | 0.816 | 0.230 / 0.286 |
| baseline: injection_time | 0.634 +/- 0.029 | 0.699 | 0.649 | 0.619 | 0.186 / 0.403 |
| baseline: batch | 0.495 +/- 0.042 | 0.479 | 0.268 | 0.722 | 0.000 / 0.024 |
| baseline: mode | 0.484 +/- 0.030 | 0.469 | 0.408 | 0.559 | 0.000 / 0.030 |

network_minus_host (BA, per fold assignment): -0.128 +/- 0.043, positive in 0 of 10

concat_minus_host (BA, per fold assignment): -0.005 +/- 0.033, positive in 4 of 10

stacked_minus_host (BA, per fold assignment): +0.011 +/- 0.030, positive in 6 of 10

Seen families (stratified folds, rows of one family in training and test):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.826 +/- 0.031 | 0.858 | 0.789 | 0.862 |
| network | 0.699 +/- 0.014 | 0.652 | 0.535 | 0.862 |
| concat | 0.804 +/- 0.030 | 0.874 | 0.765 | 0.843 |
| stacked | 0.826 +/- 0.029 | 0.860 | 0.792 | 0.859 |

Share flagged per group (mean over fold assignments; malicious groups: recall):

| group | label | rows | host | network | concat | stacked |
|---|---|---|---|---|---|---|
| attack::syn-sink-40k | 1 | 1 | 0% | 100% | 0% | 0% |
| attack::udp-direct-40k | 1 | 1 | 0% | 100% | 0% | 0% |
| family::Akira | 1 | 1 | 90% | 0% | 90% | 50% |
| family::Bert | 1 | 1 | 80% | 0% | 40% | 80% |
| family::BillGates | 1 | 1 | 100% | 100% | 100% | 100% |
| family::BrickStorm | 1 | 1 | 0% | 0% | 0% | 0% |
| family::CatStorm | 1 | 1 | 100% | 0% | 100% | 100% |
| family::Chaos | 1 | 1 | 100% | 0% | 100% | 100% |
| family::ChinaZ | 1 | 1 | 100% | 0% | 80% | 100% |
| family::CoinMiner | 1 | 2 | 100% | 50% | 100% | 100% |
| family::DDoSAgent | 1 | 1 | 100% | 0% | 50% | 90% |
| family::DeskRAT | 1 | 1 | 100% | 0% | 90% | 100% |
| family::Dofloo | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Gafgyt | 1 | 1 | 100% | 100% | 100% | 100% |
| family::GetShell | 1 | 1 | 80% | 0% | 80% | 80% |
| family::INC | 1 | 1 | 0% | 0% | 10% | 0% |
| family::Kaiji | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Kaiten | 1 | 1 | 80% | 100% | 100% | 100% |
| family::Katana | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Mirai | 1 | 2 | 100% | 50% | 100% | 100% |
| family::Ngioweb | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Nitrogen | 1 | 1 | 0% | 0% | 0% | 0% |
| family::NoEscape | 1 | 1 | 100% | 0% | 100% | 100% |
| family::Prometei | 1 | 1 | 100% | 0% | 100% | 100% |
| family::PromptLock | 1 | 1 | 0% | 100% | 70% | 80% |
| family::Qilin | 1 | 1 | 0% | 0% | 0% | 0% |
| family::RapperBot | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Tsunami | 1 | 6 | 92% | 83% | 100% | 100% |
| benign::archive-docs | 0 | 1 | 100% | 0% | 100% | 100% |
| benign::browse-public | 0 | 1 | 0% | 40% | 0% | 0% |
| benign::checkin-public | 0 | 1 | 0% | 10% | 0% | 0% |
| benign::dns-poll | 0 | 1 | 0% | 100% | 30% | 10% |
| benign::download-burst | 0 | 1 | 0% | 20% | 10% | 10% |
| benign::file-search | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_amd64_dynamic-start | 0 | 1 | 80% | 0% | 80% | 70% |
| null::null-native_amd64_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_i386_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-true | 0 | 1 | 0% | 0% | 0% | 0% |
| project::brotli | 0 | 1 | 30% | 0% | 10% | 0% |
| project::bzip2 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::coreutils | 0 | 2 | 10% | 0% | 20% | 0% |
| project::cpio | 0 | 1 | 0% | 0% | 0% | 0% |
| project::curl | 0 | 1 | 0% | 70% | 30% | 0% |
| project::diffutils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::expat | 0 | 1 | 0% | 0% | 20% | 0% |
| project::git | 0 | 1 | 0% | 0% | 0% | 0% |
| project::gzip | 0 | 2 | 5% | 0% | 10% | 0% |
| project::inetutils | 0 | 1 | 0% | 100% | 10% | 60% |
| project::jq | 0 | 1 | 0% | 0% | 0% | 0% |
| project::libzstd | 0 | 1 | 0% | 0% | 0% | 0% |
| project::lz4 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::m4 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::ncompress | 0 | 2 | 0% | 0% | 0% | 0% |
| project::openssl | 0 | 1 | 0% | 0% | 0% | 0% |
| project::rsync | 0 | 1 | 90% | 0% | 40% | 50% |
| project::sqlite3 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::tar | 0 | 1 | 0% | 0% | 0% | 0% |
| project::unzip | 0 | 1 | 0% | 0% | 0% | 0% |
| project::wget | 0 | 1 | 20% | 80% | 30% | 70% |
| project::xxhash | 0 | 1 | 0% | 0% | 0% | 0% |
| project::xz-utils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::zip | 0 | 1 | 0% | 0% | 0% | 0% |

## Per-program rows, 80s (n 74, malicious 37)


Grouped CV within the session rows (families / projects held out): 

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.855 +/- 0.049 | 0.864 | 0.784 | 0.927 | 0.722 / 0.792 |
| network | 0.700 +/- 0.023 | 0.694 | 0.522 | 0.878 | 0.411 / 0.503 |
| concat | 0.835 +/- 0.029 | 0.897 | 0.773 | 0.897 | 0.681 / 0.778 |
| stacked | 0.851 +/- 0.026 | 0.877 | 0.800 | 0.903 | 0.708 / 0.795 |
| baseline: activity | 0.661 +/- 0.024 | 0.725 | 0.608 | 0.714 | 0.341 / 0.432 |
| baseline: lifetime | 0.649 +/- 0.046 | 0.634 | 0.476 | 0.822 | 0.246 / 0.289 |
| baseline: injection_time | 0.634 +/- 0.029 | 0.699 | 0.649 | 0.619 | 0.186 / 0.403 |
| baseline: batch | 0.495 +/- 0.042 | 0.479 | 0.268 | 0.722 | 0.000 / 0.024 |
| baseline: mode | 0.484 +/- 0.030 | 0.469 | 0.408 | 0.559 | 0.000 / 0.030 |

network_minus_host (BA, per fold assignment): -0.155 +/- 0.049, positive in 0 of 10

concat_minus_host (BA, per fold assignment): -0.020 +/- 0.031, positive in 1 of 10

stacked_minus_host (BA, per fold assignment): -0.004 +/- 0.034, positive in 2 of 10

Seen families (stratified folds, rows of one family in training and test):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.845 +/- 0.029 | 0.860 | 0.797 | 0.892 |
| network | 0.705 +/- 0.019 | 0.674 | 0.559 | 0.851 |
| concat | 0.814 +/- 0.029 | 0.880 | 0.754 | 0.873 |
| stacked | 0.835 +/- 0.034 | 0.860 | 0.778 | 0.892 |

Share flagged per group (mean over fold assignments; malicious groups: recall):

| group | label | rows | host | network | concat | stacked |
|---|---|---|---|---|---|---|
| attack::syn-sink-40k | 1 | 1 | 0% | 100% | 0% | 0% |
| attack::udp-direct-40k | 1 | 1 | 0% | 100% | 0% | 0% |
| family::Akira | 1 | 1 | 80% | 0% | 80% | 30% |
| family::Bert | 1 | 1 | 80% | 0% | 20% | 80% |
| family::BillGates | 1 | 1 | 100% | 100% | 100% | 100% |
| family::BrickStorm | 1 | 1 | 0% | 0% | 0% | 0% |
| family::CatStorm | 1 | 1 | 100% | 0% | 100% | 100% |
| family::Chaos | 1 | 1 | 100% | 0% | 100% | 100% |
| family::ChinaZ | 1 | 1 | 100% | 0% | 80% | 100% |
| family::CoinMiner | 1 | 2 | 100% | 50% | 100% | 100% |
| family::DDoSAgent | 1 | 1 | 90% | 0% | 0% | 70% |
| family::DeskRAT | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Dofloo | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Gafgyt | 1 | 1 | 100% | 70% | 100% | 100% |
| family::GetShell | 1 | 1 | 80% | 0% | 80% | 80% |
| family::INC | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Kaiji | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Kaiten | 1 | 1 | 80% | 100% | 100% | 100% |
| family::Katana | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Mirai | 1 | 2 | 100% | 50% | 100% | 100% |
| family::Ngioweb | 1 | 2 | 100% | 30% | 100% | 100% |
| family::Nitrogen | 1 | 1 | 0% | 0% | 0% | 0% |
| family::NoEscape | 1 | 1 | 100% | 0% | 100% | 100% |
| family::Prometei | 1 | 1 | 100% | 0% | 100% | 100% |
| family::PromptLock | 1 | 1 | 40% | 100% | 100% | 100% |
| family::Qilin | 1 | 1 | 0% | 0% | 0% | 0% |
| family::RapperBot | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Tsunami | 1 | 6 | 92% | 83% | 100% | 100% |
| benign::archive-docs | 0 | 1 | 100% | 0% | 100% | 100% |
| benign::browse-public | 0 | 1 | 0% | 10% | 0% | 0% |
| benign::checkin-public | 0 | 1 | 0% | 70% | 20% | 0% |
| benign::dns-poll | 0 | 1 | 0% | 100% | 70% | 70% |
| benign::download-burst | 0 | 1 | 0% | 10% | 0% | 0% |
| benign::file-search | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_amd64_dynamic-start | 0 | 1 | 80% | 0% | 80% | 70% |
| null::null-native_amd64_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_i386_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-true | 0 | 1 | 0% | 0% | 0% | 0% |
| project::brotli | 0 | 1 | 40% | 0% | 20% | 10% |
| project::bzip2 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::coreutils | 0 | 2 | 5% | 0% | 10% | 0% |
| project::cpio | 0 | 1 | 0% | 0% | 0% | 0% |
| project::curl | 0 | 1 | 0% | 70% | 10% | 0% |
| project::diffutils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::expat | 0 | 1 | 10% | 0% | 20% | 0% |
| project::git | 0 | 1 | 0% | 0% | 0% | 0% |
| project::gzip | 0 | 2 | 5% | 0% | 10% | 0% |
| project::inetutils | 0 | 1 | 0% | 100% | 0% | 30% |
| project::jq | 0 | 1 | 0% | 0% | 0% | 0% |
| project::libzstd | 0 | 1 | 0% | 0% | 0% | 0% |
| project::lz4 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::m4 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::ncompress | 0 | 2 | 0% | 0% | 0% | 0% |
| project::openssl | 0 | 1 | 0% | 10% | 0% | 0% |
| project::rsync | 0 | 1 | 20% | 0% | 10% | 20% |
| project::sqlite3 | 0 | 1 | 0% | 0% | 0% | 0% |
| project::tar | 0 | 1 | 0% | 0% | 0% | 0% |
| project::unzip | 0 | 1 | 0% | 0% | 0% | 0% |
| project::wget | 0 | 1 | 0% | 80% | 10% | 60% |
| project::xxhash | 0 | 1 | 0% | 0% | 0% | 0% |
| project::xz-utils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::zip | 0 | 1 | 0% | 0% | 0% | 0% |

## 10-s machine windows (n 168, malicious 37)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.552 +/- 0.021 | 0.817 | 0.165 | 0.938 | 0.130 / 0.319 |
| network | 0.562 +/- 0.022 | 0.666 | 0.132 | 0.992 | 0.251 / 0.314 |
| concat | 0.529 +/- 0.020 | 0.832 | 0.076 | 0.982 | 0.162 / 0.376 |
| stacked | 0.769 +/- 0.032 | 0.826 | 0.773 | 0.765 | 0.138 / 0.324 |
| activity baseline | 0.630 +/- 0.028 | 0.698 | 0.427 | 0.832 | 0.235 / 0.322 |
| position baseline | 0.624 +/- 0.024 | 0.729 | 0.454 | 0.794 | 0.251 / 0.343 |

network_minus_host (BA, per fold assignment): +0.011 +/- 0.028, positive in 8 of 10

concat_minus_host (BA, per fold assignment): -0.023 +/- 0.023, positive in 2 of 10

stacked_minus_host (BA, per fold assignment): +0.217 +/- 0.030, positive in 10 of 10

Seen families (stratified folds):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.620 +/- 0.030 | 0.856 | 0.303 | 0.938 |
| network | 0.604 +/- 0.015 | 0.656 | 0.214 | 0.995 |
| concat | 0.586 +/- 0.015 | 0.863 | 0.192 | 0.980 |
| stacked | 0.797 +/- 0.021 | 0.862 | 0.814 | 0.780 |

## 30-s machine windows (n 168, malicious 37)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.630 +/- 0.033 | 0.806 | 0.295 | 0.965 | 0.332 / 0.457 |
| network | 0.536 +/- 0.010 | 0.666 | 0.084 | 0.988 | 0.149 / 0.238 |
| concat | 0.588 +/- 0.031 | 0.810 | 0.197 | 0.978 | 0.343 / 0.476 |
| stacked | 0.740 +/- 0.024 | 0.808 | 0.689 | 0.791 | 0.349 / 0.497 |
| activity baseline | 0.493 +/- 0.036 | 0.542 | 0.222 | 0.764 | 0.041 / 0.078 |
| position baseline | 0.696 +/- 0.027 | 0.784 | 0.570 | 0.821 | 0.311 / 0.457 |

network_minus_host (BA, per fold assignment): -0.094 +/- 0.032, positive in 0 of 10

concat_minus_host (BA, per fold assignment): -0.042 +/- 0.028, positive in 0 of 10

stacked_minus_host (BA, per fold assignment): +0.110 +/- 0.032, positive in 10 of 10

Seen families (stratified folds):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.696 +/- 0.030 | 0.836 | 0.432 | 0.960 |
| network | 0.588 +/- 0.022 | 0.721 | 0.192 | 0.983 |
| concat | 0.668 +/- 0.020 | 0.859 | 0.357 | 0.979 |
| stacked | 0.787 +/- 0.027 | 0.852 | 0.762 | 0.811 |

## Lab cue (a connection left unanswered)

BA 0.514, recall 0.027, specificity 1.000; flagged by kind {"attack": 0.5, "benign": 0.0, "malware": 0.0, "null": 0.0}
