## Sessions

| attempt | plan | run | accepted | rejected | failed | min/session (median) | Sink packets (median) | clock drift ms (range) | flows attributed |
|---|---|---|---|---|---|---|---|---|---|
| 20261115T213142604626Z | pilot | 20 of 20 | 20 | 0 | 0 | 4.1 | 2446.0 | -91.8 to -91.1 | 100% |
| 20261115T214153675625Z | main | 111 of 254 | 104 | 3 | 3 | 4.1 | 8793.5 | -183.3 to -91.0 | 100% |

- m010 attack syn-sink-40k (rejected): capture {'counters': {'captured': 128768, 'received': 128834, 'dropped': 66}, 'fetched': True, 'killed': False}
- m018 malware LockBit-4dc06ece (failed): ValueError: Guest login event timed out
- m030 attack syn-fan-40k (rejected): host-b.log: health ['HOSTMON_HEALTH,0,39761,0,0']
- m070 attack udp-fan-40k (rejected): capture {'counters': {'captured': 47792, 'received': 48626, 'dropped': 834}, 'fetched': True, 'killed': False}
- m084 benign wget-wget-0a23aee0 (failed): ValueError: Guest login event timed out
- m109 benign compress-ncompress-3a676dd1 (failed): ValueError: Guest login event timed out
- m111 malware GetShell-1dbfe7a5 (missing): ?

Programs that never started (only the waiting shell's and the launch wrapper's calls in their cgroup; left out of detection, as the dataset left out runs without an observed exec):

- m028 malware NoEscape-d7e5d1da (20261115T214153675625Z)
- m033 malware CoinMiner-9e5b93d3 (20261115T214153675625Z)
- m036 malware Tsunami-061c6641 (20261115T214153675625Z)
- m046 malware Chaos-6d29b886 (20261115T214153675625Z)
- m091 malware Tsunami-16453982 (20261115T214153675625Z)

## Malware behaviour: dataset run (20 s) vs session

Session class over the whole session after injection / over its first 20 s:

| dataset lab class | session class | count |
|---|---|---|
| None | silent | 4 |
| all_answered | all_answered | 8 |
| none_answered | all_answered | 14 |
| silent | all_answered | 7 |
| silent | silent | 16 |
| some_unanswered | all_answered | 3 |

| dataset lab class | session class, first 20 s | count |
|---|---|---|
| None | silent | 4 |
| all_answered | all_answered | 8 |
| none_answered | all_answered | 14 |
| silent | all_answered | 5 |
| silent | silent | 18 |
| some_unanswered | all_answered | 3 |

| Triage (internet) class | session class | count |
|---|---|---|
| None | silent | 4 |
| all_answered | all_answered | 14 |
| none_answered | all_answered | 1 |
| silent | all_answered | 1 |
| silent | silent | 9 |
| some_unanswered | all_answered | 16 |
| some_unanswered | silent | 2 |
| uncertain | silent | 5 |

| sample | family | dataset packets / calls (20 s) | session flows (20 s / all) | answered | remotes | first contact s | DNS via resolver | session calls (20 s) | Spearman vs dataset row |
|---|---|---|---|---|---|---|---|---|---|
| 40c8a17d9b | Akira | 0.0 / 267.0 | 0 / 0 | 0 | 0 | None | 0 | 249.0 | 0.997 |
| 5bba035c4c | Bert | 0.0 / 5397.0 | 0 / 0 | 0 | 0 | None | 0 | 5404.0 | 0.998 |
| c7efe9b84b | Bert | 0.0 / 5361.0 | 0 / 0 | 0 | 0 | None | 0 | 5366.0 | 1.000 |
| 750f01a5ab | BillGates | 8.0 / 1763.0 | 1 / 1 | 1 | 1 | 5.101 | 0 | 1755.0 | 0.759 |
| 2388ed7aee | BrickStorm | 0.0 / 386.0 | 0 / 0 | 0 | 0 | None | 0 | 362.0 | 0.998 |
| aa688682d4 | BrickStorm | 0.0 / 373.0 | 0 / 0 | 0 | 0 | None | 0 | 379.0 | 0.999 |
| 80c08fc090 | CatStorm | 0.0 / 3843223.0 | 0 / 0 | 0 | 0 | None | 0 | 4256937.0 | 1.000 |
| 2d8b09556b | Chaos | 166.0 / 5264.0 | 7 / 7 | 7 | 2 | 0.606 | 6 | 3930.0 | 0.824 |
| 6d29b88651 | Chaos | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| 09bc639a01 | ChinaZ | 0.0 / 8818.0 | 0 / 0 | 0 | 0 | None | 0 | 9085.0 | 1.000 |
| 4c17a852a2 | CoinMiner | 26.0 / 1932.0 | 10 / 60 | 60 | 4 | 3.078 | 48 | 1940.0 | 0.931 |
| 8124f4ac27 | CoinMiner | 26.0 / 1920.0 | 10 / 63 | 63 | 4 | 3.056 | 51 | 1921.0 | 0.931 |
| 9e5b93d309 | CoinMiner | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| 035a6840a1 | DDoSAgent | 0.0 / 1636.0 | 0 / 0 | 0 | 0 | None | 0 | 1651.0 | 0.999 |
| 6b844ca37d | DDoSAgent | 9.0 / 708.0 | 1 / 1 | 1 | 1 | 0.017 | 0 | 684.0 | 0.755 |
| 6ed2afc550 | DeskRAT | 0.0 / 22911.0 | 0 / 24 | 24 | 2 | 44.251 | 18 | 22459.0 | 0.997 |
| f0b98f9570 | DeskRAT | 0.0 / 22880.0 | 0 / 20 | 20 | 2 | 24.553 | 15 | 49178.0 | 0.993 |
| 990628a240 | Dofloo | 10.0 / 2363.0 | 1 / 2 | 2 | 1 | 0.071 | 0 | 2566.0 | 0.739 |
| dee20b174e | Dofloo | 10.0 / 2363.0 | 1 / 2 | 2 | 1 | 0.07 | 0 | 2566.0 | 0.794 |
| 0018c8962a | Gafgyt | 9.0 / 469.0 | 1 / 1 | 1 | 1 | 0.017 | 0 | 462.0 | 0.659 |
| 00472840f6 | Gafgyt | 9.0 / 201.0 | 1 / 1 | 1 | 1 | 0.054 | 0 | 285.0 | 0.643 |
| 690711e086 | GetShell | 0.0 / 194.0 | 0 / 0 | 0 | 0 | None | 0 | 182.0 | 0.997 |
| 86d0447445 | INC | 0.0 / 278.0 | 0 / 0 | 0 | 0 | None | 0 | 266.0 | 0.997 |
| 0088509f1a | Kaiji | 15.0 / 4433.0 | 4 / 4 | 4 | 2 | 0.037 | 3 | 5113.0 | 0.939 |
| 47b6ecba4e | Kaiji | 86.0 / 7365.0 | 7 / 7 | 7 | 2 | 1.083 | 6 | 6897.0 | 0.854 |
| 4a94ce0d72 | Kaiji | 86.0 / 7454.0 | 7 / 7 | 7 | 2 | 1.085 | 6 | 6928.0 | 0.860 |
| 80b4d47bfb | Kaiten | 80.0 / 719.0 | 2 / 2 | 2 | 2 | 0.048 | 1 | 276.0 | 0.833 |
| e546ae527b | Kaiten | 14.0 / 265.0 | 1 / 1 | 1 | 1 | 0.026 | 0 | 218.0 | 0.726 |
| 6cc3fc0284 | Katana | 12.0 / 10473.0 | 2 / 2 | 2 | 2 | 0.053 | 1 | 8889.0 | 0.924 |
| 87ec57bd8e | Katana | 20.0 / 9039.0 | 2 / 2 | 2 | 2 | 0.029 | 1 | 10277.0 | 0.910 |
| 90b06f07eb | LockBit | 0.0 / 374.0 | 0 / 0 | 0 | 0 | None | 0 | 343.0 | 0.999 |
| 0007edc2bd | Mirai | 0.0 / 187.0 | 0 / 0 | 0 | 0 | None | 0 | 175.0 | 0.997 |
| 0630f475e1 | Mirai | 9.0 / 2548.0 | 1 / 1 | 1 | 1 | 0.038 | 0 | 2743.0 | 0.709 |
| 0714651541 | Mirai | 977.0 / 35654.0 | 265 / 1030 | 1030 | 541 | 0.053 | 0 | 36228.0 | 0.650 |
| d328a8df79 | Ngioweb | 8.0 / 7610.0 | 4 / 14 | 14 | 1 | 0.051 | 14 | 7598.0 | 1.000 |
| fc43bc3a09 | Ngioweb | 8.0 / 7612.0 | 4 / 18 | 18 | 1 | 0.053 | 18 | 7601.0 | 0.999 |
| 0859497eea | Nitrogen | 0.0 / 197.0 | 0 / 0 | 0 | 0 | None | 0 | 185.0 | 0.997 |
| d7e5d1da2d | NoEscape | 0.0 / 178.0 | 0 / 0 | 0 | 0 | None | 0 | 166.0 | 0.997 |
| 15e1bc61d1 | Prometei | 1.0 / 3037.0 | 2 / 2 | 2 | 2 | 6.551 | 0 | 4211.0 | 0.801 |
| 765b0ad71a | Prometei | 8.0 / 3847.0 | 1 / 11 | 11 | 4 | 10.773 | 0 | 4146.0 | 0.742 |
| 2755e1ec1e | PromptLock | 9.0 / 442.0 | 1 / 1 | 1 | 1 | 0.018 | 0 | 432.0 | 0.762 |
| 363ab6b4c7 | Qilin | 0.0 / 234.0 | 0 / 0 | 0 | 0 | None | 0 | 222.0 | 0.996 |
| 67cdee8253 | Qilin | 0.0 / 234.0 | 0 / 0 | 0 | 0 | None | 0 | 222.0 | 0.996 |
| 6c034ff9b5 | RapperBot | 21.0 / 6521.0 | 1 / 1 | 1 | 1 | 0.033 | 0 | 6400.0 | 0.735 |
| 061c664196 | Tsunami | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| 0d762c8cbb | Tsunami | 0.0 / 4735.0 | 2 / 2 | 2 | 2 | 0.05 | 1 | 9551.0 | 0.115 |
| 16453982cf | Tsunami | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| 3e16c3bc39 | Tsunami | 0.0 / 4697.0 | 2 / 2 | 2 | 2 | 0.076 | 1 | 9687.0 | 0.113 |
| 7d22fabcc9 | Tsunami | 0.0 / 4717.0 | 1 / 1 | 1 | 1 | 0.068 | 0 | 9548.0 | 0.143 |
| 86947b00a3 | Tsunami | 0.0 / 4677.0 | 1 / 1 | 1 | 1 | 0.082 | 0 | 9477.0 | 0.143 |
| 9e28f94226 | Tsunami | 0.0 / 4737.0 | 1 / 1 | 1 | 1 | 0.273 | 0 | 9511.0 | 0.143 |
| 47c0af3e02 | XorDDoS | 10.0 / 4619.0 | 9 / 34 | 34 | 3 | 0.037 | 0 | 4898.0 | 0.792 |

## Benign tasks: session (first 20 s of the program) vs dataset row

Median Spearman over 235 columns: 0.997 (42 tasks)


## Per-program rows, 20s (n 102, malicious 50)

Paper detectors trained on the 240 dataset rows, applied to the session rows:

| detector | BA | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.778 | 0.918 | 0.980 | 0.577 |
| network | 0.720 | 0.717 | 0.460 | 0.981 |
| concat | 0.817 | 0.939 | 0.980 | 0.654 |
| stacked | 0.807 | 0.932 | 0.940 | 0.673 |

Share flagged by kind: {"host": {"attack": 0.6666666666666666, "benign": 0.375, "malware": 1.0, "null": 1.0}, "network": {"attack": 0.6666666666666666, "benign": 0.020833333333333332, "malware": 0.44680851063829785, "null": 0.0}, "concat": {"attack": 0.6666666666666666, "benign": 0.2916666666666667, "malware": 1.0, "null": 1.0}, "stacked": {"attack": 0.6666666666666666, "benign": 0.2916666666666667, "malware": 0.9574468085106383, "null": 0.75}}

Start-up signature columns (dataset rows vs session rows, min / median / max):

| column | dataset | sessions |
|---|---|---|
| host_max_run_length_max__max | 54 / 54 / 52866 | 12 / 29 / 32774 |
| host_first50_unique_mean__max | 1.31223 / 5 / 23 | 1.30648 / 21 / 24.5 |
| host_first100_unique_mean__max | 6 / 15 / 27 | 8.25 / 22 / 26 |

Same transfer without the start-up-dominated host signals (host_max_run_length_mean, host_max_run_length_max, host_first50_unique_mean, host_first50_unique_max, host_first100_unique_mean, host_first100_unique_max; post hoc):

| detector | BA | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.844 | 0.931 | 0.880 | 0.808 |
| network | 0.720 | 0.717 | 0.460 | 0.981 |
| concat | 0.854 | 0.946 | 0.920 | 0.788 |
| stacked | 0.882 | 0.945 | 0.840 | 0.923 |

Share flagged by kind: {"host": {"attack": 0.3333333333333333, "benign": 0.1875, "malware": 0.9148936170212766, "null": 0.25}, "network": {"attack": 0.6666666666666666, "benign": 0.020833333333333332, "malware": 0.44680851063829785, "null": 0.0}, "concat": {"attack": 0.6666666666666666, "benign": 0.16666666666666666, "malware": 0.9361702127659575, "null": 0.75}, "stacked": {"attack": 0.6666666666666666, "benign": 0.08333333333333333, "malware": 0.851063829787234, "null": 0.0}}

Grouped CV within the session rows (families / projects held out): 

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.815 +/- 0.015 | 0.841 | 0.742 | 0.888 | 0.710 / 0.744 |
| network | 0.737 +/- 0.015 | 0.708 | 0.606 | 0.867 | 0.446 / 0.562 |
| concat | 0.820 +/- 0.031 | 0.877 | 0.778 | 0.862 | 0.696 / 0.748 |
| stacked | 0.814 +/- 0.023 | 0.855 | 0.750 | 0.879 | 0.622 / 0.736 |
| baseline: activity | 0.629 +/- 0.039 | 0.654 | 0.590 | 0.667 | 0.146 / 0.252 |
| baseline: lifetime | 0.617 +/- 0.039 | 0.589 | 0.426 | 0.808 | 0.282 / 0.306 |
| baseline: injection_time | 0.594 +/- 0.016 | 0.655 | 0.584 | 0.604 | 0.226 / 0.388 |
| baseline: batch | 0.489 +/- 0.030 | 0.470 | 0.204 | 0.773 | 0.006 / 0.058 |
| baseline: mode | 0.499 +/- 0.043 | 0.449 | 0.672 | 0.327 | 0.000 / 0.034 |

One-feature baselines on random noise (20 draws, same folds): BA mean 0.495, 95th percentile 0.582, max 0.588

network_minus_host (BA, per fold assignment): -0.079 +/- 0.014, positive in 0 of 10

concat_minus_host (BA, per fold assignment): +0.005 +/- 0.031, positive in 5 of 10

stacked_minus_host (BA, per fold assignment): -0.001 +/- 0.021, positive in 5 of 10

Seen families (stratified folds, rows of one family in training and test):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.861 +/- 0.020 | 0.893 | 0.796 | 0.927 |
| network | 0.752 +/- 0.014 | 0.756 | 0.628 | 0.875 |
| concat | 0.860 +/- 0.022 | 0.933 | 0.830 | 0.890 |
| stacked | 0.864 +/- 0.017 | 0.914 | 0.802 | 0.927 |

Share flagged per group (mean over fold assignments; malicious groups: recall):

| group | label | rows | host | network | concat | stacked |
|---|---|---|---|---|---|---|
| attack::http-flood-2k | 1 | 1 | 0% | 30% | 80% | 10% |
| attack::syn-sink-40k | 1 | 1 | 0% | 100% | 60% | 0% |
| attack::udp-direct-40k | 1 | 1 | 0% | 100% | 10% | 10% |
| family::Akira | 1 | 1 | 90% | 0% | 90% | 80% |
| family::Bert | 1 | 2 | 100% | 0% | 100% | 95% |
| family::BillGates | 1 | 1 | 100% | 100% | 100% | 100% |
| family::BrickStorm | 1 | 2 | 0% | 0% | 0% | 0% |
| family::CatStorm | 1 | 1 | 100% | 0% | 70% | 90% |
| family::Chaos | 1 | 1 | 100% | 100% | 100% | 100% |
| family::ChinaZ | 1 | 1 | 100% | 0% | 100% | 100% |
| family::CoinMiner | 1 | 2 | 100% | 100% | 100% | 100% |
| family::DDoSAgent | 1 | 2 | 50% | 50% | 100% | 100% |
| family::DeskRAT | 1 | 2 | 90% | 0% | 20% | 50% |
| family::Dofloo | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Gafgyt | 1 | 2 | 100% | 100% | 100% | 100% |
| family::GetShell | 1 | 1 | 80% | 0% | 70% | 40% |
| family::INC | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Kaiji | 1 | 3 | 100% | 100% | 100% | 100% |
| family::Kaiten | 1 | 2 | 90% | 100% | 100% | 100% |
| family::Katana | 1 | 2 | 100% | 100% | 100% | 100% |
| family::LockBit | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Mirai | 1 | 3 | 90% | 67% | 93% | 90% |
| family::Ngioweb | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Nitrogen | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Prometei | 1 | 2 | 100% | 0% | 100% | 90% |
| family::PromptLock | 1 | 1 | 10% | 100% | 90% | 80% |
| family::Qilin | 1 | 2 | 0% | 0% | 0% | 0% |
| family::RapperBot | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Tsunami | 1 | 5 | 100% | 100% | 100% | 100% |
| family::XorDDoS | 1 | 1 | 100% | 100% | 100% | 100% |
| benign::archive-docs | 0 | 1 | 100% | 0% | 100% | 100% |
| benign::browse-public | 0 | 1 | 0% | 90% | 50% | 0% |
| benign::checkin-public | 0 | 1 | 10% | 40% | 50% | 20% |
| benign::dns-poll | 0 | 1 | 10% | 100% | 90% | 100% |
| benign::download-burst | 0 | 1 | 0% | 50% | 50% | 20% |
| benign::file-search | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_amd64_dynamic-start | 0 | 1 | 20% | 0% | 20% | 10% |
| null::null-native_amd64_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_i386_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-true | 0 | 1 | 0% | 0% | 0% | 0% |
| project::brotli | 0 | 2 | 50% | 0% | 10% | 30% |
| project::bzip2 | 0 | 2 | 0% | 0% | 0% | 0% |
| project::coreutils | 0 | 2 | 15% | 0% | 15% | 10% |
| project::cpio | 0 | 2 | 0% | 0% | 0% | 0% |
| project::curl | 0 | 2 | 35% | 90% | 55% | 45% |
| project::diffutils | 0 | 2 | 15% | 0% | 0% | 10% |
| project::expat | 0 | 2 | 30% | 0% | 45% | 5% |
| project::git | 0 | 2 | 0% | 0% | 0% | 0% |
| project::gzip | 0 | 2 | 0% | 0% | 0% | 0% |
| project::inetutils | 0 | 2 | 5% | 90% | 20% | 55% |
| project::jq | 0 | 2 | 0% | 0% | 0% | 0% |
| project::libzstd | 0 | 1 | 0% | 0% | 0% | 0% |
| project::lz4 | 0 | 2 | 15% | 0% | 30% | 10% |
| project::m4 | 0 | 2 | 0% | 0% | 0% | 0% |
| project::ncompress | 0 | 2 | 0% | 0% | 0% | 0% |
| project::openssl | 0 | 2 | 0% | 20% | 0% | 5% |
| project::rsync | 0 | 2 | 50% | 0% | 0% | 20% |
| project::sqlite3 | 0 | 2 | 5% | 0% | 5% | 0% |
| project::tar | 0 | 1 | 0% | 0% | 0% | 0% |
| project::unzip | 0 | 1 | 0% | 0% | 0% | 0% |
| project::wget | 0 | 1 | 0% | 10% | 0% | 0% |
| project::xxhash | 0 | 2 | 0% | 0% | 0% | 0% |
| project::xz-utils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::zip | 0 | 1 | 0% | 0% | 0% | 0% |

## Per-program rows, 80s (n 102, malicious 50)


Grouped CV within the session rows (families / projects held out): 

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.843 +/- 0.019 | 0.853 | 0.786 | 0.900 | 0.752 / 0.786 |
| network | 0.739 +/- 0.025 | 0.723 | 0.606 | 0.871 | 0.538 / 0.588 |
| concat | 0.845 +/- 0.031 | 0.887 | 0.794 | 0.896 | 0.690 / 0.800 |
| stacked | 0.832 +/- 0.020 | 0.862 | 0.764 | 0.900 | 0.618 / 0.754 |
| baseline: activity | 0.582 +/- 0.022 | 0.596 | 0.532 | 0.633 | 0.098 / 0.212 |
| baseline: lifetime | 0.714 +/- 0.014 | 0.673 | 0.606 | 0.821 | 0.316 / 0.364 |
| baseline: injection_time | 0.594 +/- 0.016 | 0.655 | 0.584 | 0.604 | 0.226 / 0.388 |
| baseline: batch | 0.489 +/- 0.030 | 0.470 | 0.204 | 0.773 | 0.006 / 0.058 |
| baseline: mode | 0.499 +/- 0.043 | 0.449 | 0.672 | 0.327 | 0.000 / 0.034 |

One-feature baselines on random noise (20 draws, same folds): BA mean 0.495, 95th percentile 0.582, max 0.588

network_minus_host (BA, per fold assignment): -0.104 +/- 0.034, positive in 0 of 10

concat_minus_host (BA, per fold assignment): +0.002 +/- 0.024, positive in 5 of 10

stacked_minus_host (BA, per fold assignment): -0.011 +/- 0.024, positive in 2 of 10

Seen families (stratified folds, rows of one family in training and test):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.869 +/- 0.015 | 0.907 | 0.820 | 0.917 |
| network | 0.772 +/- 0.023 | 0.779 | 0.660 | 0.885 |
| concat | 0.869 +/- 0.025 | 0.940 | 0.824 | 0.913 |
| stacked | 0.872 +/- 0.020 | 0.920 | 0.812 | 0.933 |

Share flagged per group (mean over fold assignments; malicious groups: recall):

| group | label | rows | host | network | concat | stacked |
|---|---|---|---|---|---|---|
| attack::http-flood-2k | 1 | 1 | 0% | 100% | 60% | 20% |
| attack::syn-sink-40k | 1 | 1 | 0% | 100% | 60% | 0% |
| attack::udp-direct-40k | 1 | 1 | 0% | 100% | 0% | 10% |
| family::Akira | 1 | 1 | 90% | 0% | 90% | 90% |
| family::Bert | 1 | 2 | 90% | 0% | 60% | 85% |
| family::BillGates | 1 | 1 | 100% | 100% | 100% | 100% |
| family::BrickStorm | 1 | 2 | 0% | 0% | 0% | 0% |
| family::CatStorm | 1 | 1 | 100% | 0% | 100% | 90% |
| family::Chaos | 1 | 1 | 100% | 100% | 100% | 100% |
| family::ChinaZ | 1 | 1 | 100% | 0% | 90% | 100% |
| family::CoinMiner | 1 | 2 | 100% | 100% | 100% | 100% |
| family::DDoSAgent | 1 | 2 | 100% | 50% | 95% | 90% |
| family::DeskRAT | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Dofloo | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Gafgyt | 1 | 2 | 100% | 15% | 100% | 90% |
| family::GetShell | 1 | 1 | 80% | 0% | 70% | 40% |
| family::INC | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Kaiji | 1 | 3 | 100% | 100% | 100% | 100% |
| family::Kaiten | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Katana | 1 | 2 | 100% | 100% | 100% | 100% |
| family::LockBit | 1 | 1 | 0% | 0% | 10% | 0% |
| family::Mirai | 1 | 3 | 93% | 67% | 93% | 87% |
| family::Ngioweb | 1 | 2 | 100% | 60% | 100% | 100% |
| family::Nitrogen | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Prometei | 1 | 2 | 100% | 0% | 100% | 90% |
| family::PromptLock | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Qilin | 1 | 2 | 0% | 0% | 0% | 0% |
| family::RapperBot | 1 | 1 | 100% | 80% | 100% | 100% |
| family::Tsunami | 1 | 5 | 100% | 100% | 100% | 100% |
| family::XorDDoS | 1 | 1 | 100% | 100% | 100% | 100% |
| benign::archive-docs | 0 | 1 | 100% | 0% | 100% | 100% |
| benign::browse-public | 0 | 1 | 0% | 50% | 10% | 0% |
| benign::checkin-public | 0 | 1 | 10% | 90% | 90% | 50% |
| benign::dns-poll | 0 | 1 | 90% | 100% | 100% | 100% |
| benign::download-burst | 0 | 1 | 0% | 40% | 10% | 10% |
| benign::file-search | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_amd64_dynamic-start | 0 | 1 | 20% | 0% | 20% | 0% |
| null::null-native_amd64_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_i386_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-true | 0 | 1 | 0% | 0% | 0% | 0% |
| project::brotli | 0 | 2 | 20% | 0% | 0% | 5% |
| project::bzip2 | 0 | 2 | 0% | 0% | 0% | 0% |
| project::coreutils | 0 | 2 | 15% | 0% | 15% | 5% |
| project::cpio | 0 | 2 | 0% | 0% | 0% | 0% |
| project::curl | 0 | 2 | 35% | 80% | 25% | 45% |
| project::diffutils | 0 | 2 | 5% | 0% | 0% | 5% |
| project::expat | 0 | 2 | 45% | 0% | 30% | 15% |
| project::git | 0 | 2 | 0% | 0% | 0% | 0% |
| project::gzip | 0 | 2 | 0% | 0% | 0% | 0% |
| project::inetutils | 0 | 2 | 5% | 80% | 10% | 50% |
| project::jq | 0 | 2 | 0% | 0% | 0% | 0% |
| project::libzstd | 0 | 1 | 0% | 0% | 0% | 0% |
| project::lz4 | 0 | 2 | 25% | 0% | 25% | 5% |
| project::m4 | 0 | 2 | 0% | 0% | 0% | 0% |
| project::ncompress | 0 | 2 | 0% | 0% | 0% | 0% |
| project::openssl | 0 | 2 | 0% | 30% | 0% | 0% |
| project::rsync | 0 | 2 | 0% | 0% | 0% | 0% |
| project::sqlite3 | 0 | 2 | 0% | 0% | 0% | 0% |
| project::tar | 0 | 1 | 0% | 0% | 0% | 0% |
| project::unzip | 0 | 1 | 0% | 0% | 0% | 0% |
| project::wget | 0 | 1 | 0% | 10% | 0% | 0% |
| project::xxhash | 0 | 2 | 0% | 0% | 0% | 0% |
| project::xz-utils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::zip | 0 | 1 | 0% | 0% | 0% | 0% |

## Sensitivity: per-program rows, 20 s, including the programs that never started (n 107, malicious 55)

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.831 +/- 0.018 | 0.871 | 0.775 | 0.887 |
| network | 0.712 +/- 0.023 | 0.692 | 0.551 | 0.873 |
| concat | 0.842 +/- 0.023 | 0.889 | 0.798 | 0.887 |
| stacked | 0.842 +/- 0.016 | 0.875 | 0.789 | 0.894 |

## 10-s machine windows (n 238, malicious 50)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.602 +/- 0.015 | 0.852 | 0.244 | 0.960 | 0.274 / 0.406 |
| network | 0.562 +/- 0.022 | 0.750 | 0.142 | 0.983 | 0.274 / 0.374 |
| concat | 0.580 +/- 0.019 | 0.883 | 0.184 | 0.976 | 0.334 / 0.482 |
| stacked | 0.794 +/- 0.021 | 0.868 | 0.812 | 0.777 | 0.320 / 0.444 |
| activity baseline | 0.597 +/- 0.021 | 0.717 | 0.354 | 0.840 | 0.254 / 0.324 |
| position baseline | 0.605 +/- 0.030 | 0.688 | 0.424 | 0.787 | 0.240 / 0.324 |

One-feature baselines on random noise (10 draws): BA mean 0.504, 95th percentile 0.556, max 0.572

network_minus_host (BA, per fold assignment): -0.039 +/- 0.025, positive in 0 of 10

concat_minus_host (BA, per fold assignment): -0.022 +/- 0.015, positive in 0 of 10

stacked_minus_host (BA, per fold assignment): +0.193 +/- 0.028, positive in 10 of 10

Seen families (stratified folds):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.656 +/- 0.022 | 0.873 | 0.364 | 0.948 |
| network | 0.600 +/- 0.019 | 0.773 | 0.214 | 0.987 |
| concat | 0.630 +/- 0.019 | 0.901 | 0.282 | 0.977 |
| stacked | 0.805 +/- 0.037 | 0.891 | 0.808 | 0.803 |

## 30-s machine windows (n 238, malicious 50)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.643 +/- 0.015 | 0.853 | 0.314 | 0.972 | 0.352 / 0.472 |
| network | 0.549 +/- 0.017 | 0.740 | 0.134 | 0.964 | 0.200 / 0.378 |
| concat | 0.639 +/- 0.020 | 0.856 | 0.290 | 0.988 | 0.460 / 0.564 |
| stacked | 0.766 +/- 0.031 | 0.854 | 0.716 | 0.816 | 0.428 / 0.534 |
| activity baseline | 0.528 +/- 0.032 | 0.551 | 0.264 | 0.791 | 0.138 / 0.156 |
| position baseline | 0.665 +/- 0.035 | 0.761 | 0.508 | 0.822 | 0.216 / 0.398 |

One-feature baselines on random noise (10 draws): BA mean 0.504, 95th percentile 0.556, max 0.572

network_minus_host (BA, per fold assignment): -0.094 +/- 0.024, positive in 0 of 10

concat_minus_host (BA, per fold assignment): -0.004 +/- 0.016, positive in 2 of 10

stacked_minus_host (BA, per fold assignment): +0.123 +/- 0.028, positive in 10 of 10

Seen families (stratified folds):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.682 +/- 0.009 | 0.873 | 0.398 | 0.966 |
| network | 0.624 +/- 0.025 | 0.768 | 0.276 | 0.973 |
| concat | 0.701 +/- 0.016 | 0.876 | 0.414 | 0.989 |
| stacked | 0.795 +/- 0.010 | 0.878 | 0.750 | 0.841 |

## Lab cue (a connection left unanswered)

BA 0.510, recall 0.020, specificity 1.000; flagged by kind {"attack": 0.3333333333333333, "benign": 0.0, "malware": 0.0, "null": 0.0}
