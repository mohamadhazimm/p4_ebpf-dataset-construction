## Sessions

| attempt | plan | run | accepted | rejected | failed | min/session (median) | Sink packets (median) | clock drift ms (range) | flows attributed |
|---|---|---|---|---|---|---|---|---|---|
| 20261115T213142604626Z | pilot | 20 of 20 | 20 | 0 | 0 | 4.1 | 2446.0 | -91.8 to -91.1 | 100% |
| 20261115T214153675625Z | main | 163 of 254 | 155 | 3 | 5 | 4.1 | 8738 | -183.3 to -91.0 | 100% |

- m010 attack syn-sink-40k (rejected): capture {'counters': {'captured': 128768, 'received': 128834, 'dropped': 66}, 'fetched': True, 'killed': False}
- m018 malware LockBit-4dc06ece (failed): ValueError: Guest login event timed out
- m030 attack syn-fan-40k (rejected): host-b.log: health ['HOSTMON_HEALTH,0,39761,0,0']
- m070 attack udp-fan-40k (rejected): capture {'counters': {'captured': 47792, 'received': 48626, 'dropped': 834}, 'fetched': True, 'killed': False}
- m084 benign wget-wget-0a23aee0 (failed): ValueError: Guest login event timed out
- m109 benign compress-ncompress-3a676dd1 (failed): ValueError: Guest login event timed out
- m112 benign wc-coreutils-26918ea0 (failed): ValueError: Guest login event timed out
- m114 benign gzip-gzip-e8660b02 (failed): ValueError: Guest login event timed out

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
| all_answered | all_answered | 9 |
| none_answered | all_answered | 22 |
| silent | all_answered | 7 |
| silent | silent | 25 |
| some_unanswered | all_answered | 7 |

| dataset lab class | session class, first 20 s | count |
|---|---|---|
| None | silent | 4 |
| all_answered | all_answered | 9 |
| none_answered | all_answered | 22 |
| silent | all_answered | 5 |
| silent | silent | 27 |
| some_unanswered | all_answered | 7 |

| Triage (internet) class | session class | count |
|---|---|---|
| None | silent | 4 |
| all_answered | all_answered | 17 |
| all_answered | silent | 1 |
| none_answered | all_answered | 4 |
| silent | all_answered | 3 |
| silent | silent | 15 |
| some_unanswered | all_answered | 21 |
| some_unanswered | silent | 3 |
| uncertain | silent | 6 |

| sample | family | dataset packets / calls (20 s) | session flows (20 s / all) | answered | remotes | first contact s | DNS via resolver | session calls (20 s) | Spearman vs dataset row |
|---|---|---|---|---|---|---|---|---|---|
| 1bc4c339b1 | Akira | 0.0 / 290.0 | 0 / 0 | 0 | 0 | None | 0 | 279.0 | 0.997 |
| 40c8a17d9b | Akira | 0.0 / 267.0 | 0 / 0 | 0 | 0 | None | 0 | 249.0 | 0.997 |
| 5f73fd2184 | Akira | 0.0 / 20459.0 | 0 / 0 | 0 | 0 | None | 0 | 18697.0 | 1.000 |
| 5bba035c4c | Bert | 0.0 / 5397.0 | 0 / 0 | 0 | 0 | None | 0 | 5404.0 | 0.998 |
| c7efe9b84b | Bert | 0.0 / 5361.0 | 0 / 0 | 0 | 0 | None | 0 | 5366.0 | 1.000 |
| 750f01a5ab | BillGates | 8.0 / 1763.0 | 1 / 1 | 1 | 1 | 5.101 | 0 | 1755.0 | 0.759 |
| 2388ed7aee | BrickStorm | 0.0 / 386.0 | 0 / 0 | 0 | 0 | None | 0 | 362.0 | 0.998 |
| 320a0b5d49 | BrickStorm | 9.0 / 395.0 | 14 / 14 | 14 | 12 | 0.014 | 3 | 1307.0 | 0.506 |
| 90b760ed1d | BrickStorm | 0.0 / 382.0 | 0 / 0 | 0 | 0 | None | 0 | 367.0 | 0.999 |
| aa688682d4 | BrickStorm | 0.0 / 373.0 | 0 / 0 | 0 | 0 | None | 0 | 379.0 | 0.999 |
| 80c08fc090 | CatStorm | 0.0 / 3843223.0 | 0 / 0 | 0 | 0 | None | 0 | 4256937.0 | 1.000 |
| 2d8b09556b | Chaos | 166.0 / 5264.0 | 7 / 7 | 7 | 2 | 0.606 | 6 | 3930.0 | 0.824 |
| 6d29b88651 | Chaos | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| d538053ada | Chaos | 221733.0 / 2075798.0 | 7 / 7 | 7 | 2 | 0.035 | 6 | 5150.0 | 0.582 |
| 09bc639a01 | ChinaZ | 0.0 / 8818.0 | 0 / 0 | 0 | 0 | None | 0 | 9085.0 | 1.000 |
| 4c17a852a2 | CoinMiner | 26.0 / 1932.0 | 10 / 60 | 60 | 4 | 3.078 | 48 | 1940.0 | 0.931 |
| 8124f4ac27 | CoinMiner | 26.0 / 1920.0 | 10 / 63 | 63 | 4 | 3.056 | 51 | 1921.0 | 0.931 |
| 9e5b93d309 | CoinMiner | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| 035a6840a1 | DDoSAgent | 0.0 / 1636.0 | 0 / 0 | 0 | 0 | None | 0 | 1651.0 | 0.999 |
| 6b844ca37d | DDoSAgent | 9.0 / 708.0 | 1 / 1 | 1 | 1 | 0.017 | 0 | 684.0 | 0.755 |
| 6ddb9d5ac4 | DDoSAgent | 0.0 / 218.0 | 0 / 0 | 0 | 0 | None | 0 | 206.0 | 0.997 |
| 6ed2afc550 | DeskRAT | 0.0 / 22911.0 | 0 / 24 | 24 | 2 | 44.251 | 18 | 22459.0 | 0.997 |
| d62ad76a98 | DeskRAT | 25.0 / 1643.0 | 4 / 9 | 9 | 3 | 0.055 | 6 | 1647.0 | 0.943 |
| f0b98f9570 | DeskRAT | 0.0 / 22880.0 | 0 / 20 | 20 | 2 | 24.553 | 15 | 49178.0 | 0.993 |
| 147687b3bb | Dofloo | 10.0 / 2356.0 | 1 / 2 | 2 | 1 | 0.069 | 0 | 2549.0 | 0.793 |
| 1e141f34a3 | Dofloo | 10.0 / 2363.0 | 1 / 1 | 1 | 1 | 0.073 | 0 | 2566.0 | 0.739 |
| 990628a240 | Dofloo | 10.0 / 2363.0 | 1 / 2 | 2 | 1 | 0.071 | 0 | 2566.0 | 0.739 |
| dee20b174e | Dofloo | 10.0 / 2363.0 | 1 / 2 | 2 | 1 | 0.07 | 0 | 2566.0 | 0.794 |
| 0018c8962a | Gafgyt | 9.0 / 469.0 | 1 / 1 | 1 | 1 | 0.017 | 0 | 462.0 | 0.659 |
| 003afbf4ba | Gafgyt | 9.0 / 467.0 | 1 / 1 | 1 | 1 | 0.017 | 0 | 104839.0 | 0.646 |
| 003b15d63a | Gafgyt | 9.0 / 463.0 | 1 / 1 | 1 | 1 | 0.019 | 0 | 491.0 | 0.665 |
| 00472840f6 | Gafgyt | 9.0 / 201.0 | 1 / 1 | 1 | 1 | 0.054 | 0 | 285.0 | 0.643 |
| 1dbfe7a5e6 | GetShell | 0.0 / 213.0 | 0 / 0 | 0 | 0 | None | 0 | 201.0 | 0.997 |
| 690711e086 | GetShell | 0.0 / 194.0 | 0 / 0 | 0 | 0 | None | 0 | 182.0 | 0.997 |
| 86d0447445 | INC | 0.0 / 278.0 | 0 / 0 | 0 | 0 | None | 0 | 266.0 | 0.997 |
| 0088509f1a | Kaiji | 15.0 / 4433.0 | 4 / 4 | 4 | 2 | 0.037 | 3 | 5113.0 | 0.939 |
| 2e2481d90c | Kaiji | 86.0 / 7460.0 | 7 / 7 | 7 | 2 | 1.066 | 6 | 6908.0 | 0.863 |
| 4641b4c88a | Kaiji | 14.0 / 6039.0 | 4 / 4 | 4 | 2 | 1.103 | 3 | 6819.0 | 0.944 |
| 47b6ecba4e | Kaiji | 86.0 / 7365.0 | 7 / 7 | 7 | 2 | 1.083 | 6 | 6897.0 | 0.854 |
| 4a94ce0d72 | Kaiji | 86.0 / 7454.0 | 7 / 7 | 7 | 2 | 1.085 | 6 | 6928.0 | 0.860 |
| 6de97f85f6 | Kaiten | 0.0 / 1326.0 | 0 / 0 | 0 | 0 | None | 0 | 1330.0 | 0.999 |
| 80b4d47bfb | Kaiten | 80.0 / 719.0 | 2 / 2 | 2 | 2 | 0.048 | 1 | 276.0 | 0.833 |
| e546ae527b | Kaiten | 14.0 / 265.0 | 1 / 1 | 1 | 1 | 0.026 | 0 | 218.0 | 0.726 |
| 6cc3fc0284 | Katana | 12.0 / 10473.0 | 2 / 2 | 2 | 2 | 0.053 | 1 | 8889.0 | 0.924 |
| 87ec57bd8e | Katana | 20.0 / 9039.0 | 2 / 2 | 2 | 2 | 0.029 | 1 | 10277.0 | 0.910 |
| 90b06f07eb | LockBit | 0.0 / 374.0 | 0 / 0 | 0 | 0 | None | 0 | 343.0 | 0.999 |
| 0007edc2bd | Mirai | 0.0 / 187.0 | 0 / 0 | 0 | 0 | None | 0 | 175.0 | 0.997 |
| 00086f0430 | Mirai | 0.0 / 197.0 | 0 / 0 | 0 | 0 | None | 0 | 185.0 | 0.997 |
| 0630f475e1 | Mirai | 9.0 / 2548.0 | 1 / 1 | 1 | 1 | 0.038 | 0 | 2743.0 | 0.709 |
| 0714651541 | Mirai | 977.0 / 35654.0 | 265 / 1030 | 1030 | 541 | 0.053 | 0 | 36228.0 | 0.650 |
| 21bfeda7cf | Mirai | 12.0 / 534.0 | 20 / 80 | 80 | 2 | 0.102 | 0 | 824.0 | 0.669 |
| d328a8df79 | Ngioweb | 8.0 / 7610.0 | 4 / 14 | 14 | 1 | 0.051 | 14 | 7598.0 | 1.000 |
| fc43bc3a09 | Ngioweb | 8.0 / 7612.0 | 4 / 18 | 18 | 1 | 0.053 | 18 | 7601.0 | 0.999 |
| 0859497eea | Nitrogen | 0.0 / 197.0 | 0 / 0 | 0 | 0 | None | 0 | 185.0 | 0.997 |
| d7e5d1da2d | NoEscape | 0.0 / 178.0 | 0 / 0 | 0 | 0 | None | 0 | 166.0 | 0.997 |
| 15e1bc61d1 | Prometei | 1.0 / 3037.0 | 2 / 2 | 2 | 2 | 6.551 | 0 | 4211.0 | 0.801 |
| 765b0ad71a | Prometei | 8.0 / 3847.0 | 1 / 11 | 11 | 4 | 10.773 | 0 | 4146.0 | 0.742 |
| 2755e1ec1e | PromptLock | 9.0 / 442.0 | 1 / 1 | 1 | 1 | 0.018 | 0 | 432.0 | 0.762 |
| 363ab6b4c7 | Qilin | 0.0 / 234.0 | 0 / 0 | 0 | 0 | None | 0 | 222.0 | 0.996 |
| 67cdee8253 | Qilin | 0.0 / 234.0 | 0 / 0 | 0 | 0 | None | 0 | 222.0 | 0.996 |
| 7a9072dc37 | Qilin | 0.0 / 234.0 | 0 / 0 | 0 | 0 | None | 0 | 222.0 | 0.996 |
| a7f2a21c0c | Qilin | 0.0 / 234.0 | 0 / 0 | 0 | 0 | None | 0 | 222.0 | 0.996 |
| 6c034ff9b5 | RapperBot | 21.0 / 6521.0 | 1 / 1 | 1 | 1 | 0.033 | 0 | 6400.0 | 0.735 |
| 061c664196 | Tsunami | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| 0d762c8cbb | Tsunami | 0.0 / 4735.0 | 2 / 2 | 2 | 2 | 0.05 | 1 | 9551.0 | 0.115 |
| 16453982cf | Tsunami | None / None | 0 / 0 | 0 | 0 | None | 0 | 166.0 | - |
| 32fbfe3150 | Tsunami | 14.0 / 265.0 | 1 / 1 | 1 | 1 | 0.058 | 0 | 219.0 | 0.707 |
| 3e16c3bc39 | Tsunami | 0.0 / 4697.0 | 2 / 2 | 2 | 2 | 0.076 | 1 | 9687.0 | 0.113 |
| 7d22fabcc9 | Tsunami | 0.0 / 4717.0 | 1 / 1 | 1 | 1 | 0.068 | 0 | 9548.0 | 0.143 |
| 86947b00a3 | Tsunami | 0.0 / 4677.0 | 1 / 1 | 1 | 1 | 0.082 | 0 | 9477.0 | 0.143 |
| 8f622584f7 | Tsunami | 14.0 / 318.0 | 1 / 1 | 1 | 1 | 0.019 | 0 | 194.0 | 0.726 |
| 9e28f94226 | Tsunami | 0.0 / 4737.0 | 1 / 1 | 1 | 1 | 0.273 | 0 | 9511.0 | 0.143 |
| 47c0af3e02 | XorDDoS | 10.0 / 4619.0 | 9 / 34 | 34 | 3 | 0.037 | 0 | 4898.0 | 0.792 |
| 4c91eb5a7b | XorDDoS | 15.0 / 4631.0 | 8 / 42 | 42 | 2 | 0.064 | 0 | 4875.0 | 0.988 |

## Benign tasks: session (first 20 s of the program) vs dataset row

Median Spearman over 235 columns: 0.997 (61 tasks)


Injection times (a check that the seeded times carry no label): median 70.0 s for malicious programs, 65.4 s for benign and null; Mann-Whitney p = 0.32

## Per-program rows, 20s (n 143, malicious 72)

Paper detectors trained on the 240 dataset rows, applied to the session rows:

| detector | BA | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.775 | 0.924 | 0.972 | 0.577 |
| network | 0.715 | 0.739 | 0.444 | 0.986 |
| concat | 0.838 | 0.944 | 0.972 | 0.704 |
| stacked | 0.838 | 0.935 | 0.944 | 0.732 |

Share flagged by kind: {"host": {"attack": 0.6666666666666666, "benign": 0.3880597014925373, "malware": 0.9855072463768116, "null": 1.0}, "network": {"attack": 0.6666666666666666, "benign": 0.014925373134328358, "malware": 0.43478260869565216, "null": 0.0}, "concat": {"attack": 0.6666666666666666, "benign": 0.2537313432835821, "malware": 0.9855072463768116, "null": 1.0}, "stacked": {"attack": 0.6666666666666666, "benign": 0.23880597014925373, "malware": 0.9565217391304348, "null": 0.75}}

Start-up signature columns (dataset rows vs session rows, min / median / max):

| column | dataset | sessions |
|---|---|---|
| host_max_run_length_max__max | 54 / 54 / 52866 | 12 / 33 / 32774 |
| host_first50_unique_mean__max | 1.31223 / 5 / 23 | 1.30648 / 21 / 24.5 |
| host_first100_unique_mean__max | 6 / 15 / 27 | 8.25 / 22 / 26 |

Same transfer without the start-up-dominated host signals (host_max_run_length_mean, host_max_run_length_max, host_first50_unique_mean, host_first50_unique_max, host_first100_unique_mean, host_first100_unique_max; post hoc):

| detector | BA | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.860 | 0.933 | 0.889 | 0.831 |
| network | 0.715 | 0.739 | 0.444 | 0.986 |
| concat | 0.867 | 0.950 | 0.917 | 0.817 |
| stacked | 0.875 | 0.944 | 0.819 | 0.930 |

Share flagged by kind: {"host": {"attack": 0.3333333333333333, "benign": 0.16417910447761194, "malware": 0.9130434782608695, "null": 0.25}, "network": {"attack": 0.6666666666666666, "benign": 0.014925373134328358, "malware": 0.43478260869565216, "null": 0.0}, "concat": {"attack": 0.6666666666666666, "benign": 0.14925373134328357, "malware": 0.927536231884058, "null": 0.75}, "stacked": {"attack": 0.6666666666666666, "benign": 0.07462686567164178, "malware": 0.8260869565217391, "null": 0.0}}

Grouped CV within the session rows (families / projects held out): 

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.800 +/- 0.016 | 0.852 | 0.738 | 0.862 | 0.686 / 0.713 |
| network | 0.717 +/- 0.012 | 0.712 | 0.581 | 0.854 | 0.438 / 0.537 |
| concat | 0.795 +/- 0.025 | 0.872 | 0.758 | 0.832 | 0.656 / 0.729 |
| stacked | 0.794 +/- 0.018 | 0.840 | 0.731 | 0.858 | 0.640 / 0.710 |
| baseline: activity | 0.552 +/- 0.032 | 0.578 | 0.512 | 0.592 | 0.115 / 0.212 |
| baseline: lifetime | 0.607 +/- 0.024 | 0.567 | 0.429 | 0.785 | 0.229 / 0.257 |
| baseline: injection_time | 0.580 +/- 0.014 | 0.601 | 0.589 | 0.572 | 0.069 / 0.179 |
| baseline: batch | 0.491 +/- 0.034 | 0.425 | 0.201 | 0.780 | 0.019 / 0.075 |
| baseline: mode | 0.505 +/- 0.027 | 0.465 | 0.689 | 0.321 | 0.000 / 0.011 |

One-feature baselines on random noise (20 draws, same folds): BA mean 0.476, 95th percentile 0.517, max 0.549

network_minus_host (BA, per fold assignment): -0.083 +/- 0.020, positive in 0 of 10

concat_minus_host (BA, per fold assignment): -0.004 +/- 0.019, positive in 4 of 10

stacked_minus_host (BA, per fold assignment): -0.006 +/- 0.017, positive in 4 of 10

Seen families (stratified folds, rows of one family in training and test):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.860 +/- 0.018 | 0.925 | 0.825 | 0.894 |
| network | 0.759 +/- 0.006 | 0.767 | 0.596 | 0.923 |
| concat | 0.862 +/- 0.014 | 0.946 | 0.860 | 0.863 |
| stacked | 0.877 +/- 0.019 | 0.938 | 0.835 | 0.918 |

Share flagged per group (mean over fold assignments; malicious groups: recall):

| group | label | rows | host | network | concat | stacked |
|---|---|---|---|---|---|---|
| attack::http-flood-2k | 1 | 1 | 0% | 50% | 90% | 0% |
| attack::syn-sink-40k | 1 | 1 | 0% | 100% | 70% | 0% |
| attack::udp-direct-40k | 1 | 1 | 0% | 100% | 10% | 0% |
| family::Akira | 1 | 3 | 100% | 0% | 100% | 93% |
| family::Bert | 1 | 2 | 100% | 0% | 85% | 100% |
| family::BillGates | 1 | 1 | 100% | 100% | 100% | 100% |
| family::BrickStorm | 1 | 4 | 0% | 0% | 0% | 0% |
| family::CatStorm | 1 | 1 | 100% | 0% | 100% | 90% |
| family::Chaos | 1 | 2 | 100% | 100% | 100% | 100% |
| family::ChinaZ | 1 | 1 | 100% | 0% | 100% | 100% |
| family::CoinMiner | 1 | 2 | 100% | 100% | 100% | 100% |
| family::DDoSAgent | 1 | 3 | 47% | 33% | 67% | 63% |
| family::DeskRAT | 1 | 3 | 100% | 33% | 77% | 93% |
| family::Dofloo | 1 | 4 | 100% | 100% | 100% | 100% |
| family::Gafgyt | 1 | 4 | 100% | 92% | 100% | 100% |
| family::GetShell | 1 | 2 | 45% | 0% | 35% | 50% |
| family::INC | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Kaiji | 1 | 5 | 100% | 100% | 100% | 100% |
| family::Kaiten | 1 | 3 | 67% | 67% | 67% | 67% |
| family::Katana | 1 | 2 | 100% | 100% | 100% | 100% |
| family::LockBit | 1 | 1 | 40% | 0% | 50% | 10% |
| family::Mirai | 1 | 5 | 78% | 52% | 76% | 74% |
| family::Ngioweb | 1 | 2 | 100% | 100% | 100% | 100% |
| family::Nitrogen | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Prometei | 1 | 2 | 100% | 0% | 100% | 80% |
| family::PromptLock | 1 | 1 | 50% | 100% | 90% | 80% |
| family::Qilin | 1 | 4 | 0% | 0% | 0% | 0% |
| family::RapperBot | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Tsunami | 1 | 7 | 100% | 100% | 100% | 100% |
| family::XorDDoS | 1 | 2 | 100% | 100% | 100% | 100% |
| benign::archive-docs | 0 | 1 | 100% | 0% | 100% | 100% |
| benign::browse-public | 0 | 1 | 0% | 80% | 70% | 10% |
| benign::checkin-public | 0 | 1 | 20% | 90% | 70% | 30% |
| benign::dns-poll | 0 | 1 | 20% | 100% | 100% | 90% |
| benign::download-burst | 0 | 1 | 0% | 100% | 10% | 0% |
| benign::file-search | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_amd64_dynamic-start | 0 | 1 | 70% | 0% | 40% | 40% |
| null::null-native_amd64_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_i386_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-true | 0 | 1 | 0% | 0% | 0% | 0% |
| project::brotli | 0 | 4 | 38% | 0% | 12% | 28% |
| project::bzip2 | 0 | 3 | 0% | 0% | 0% | 0% |
| project::coreutils | 0 | 3 | 20% | 0% | 30% | 20% |
| project::cpio | 0 | 2 | 0% | 0% | 0% | 0% |
| project::curl | 0 | 4 | 20% | 40% | 35% | 20% |
| project::diffutils | 0 | 3 | 0% | 0% | 0% | 0% |
| project::expat | 0 | 3 | 70% | 0% | 80% | 60% |
| project::git | 0 | 2 | 0% | 0% | 0% | 0% |
| project::gzip | 0 | 2 | 5% | 0% | 5% | 0% |
| project::inetutils | 0 | 4 | 18% | 88% | 20% | 42% |
| project::jq | 0 | 2 | 0% | 0% | 0% | 0% |
| project::libzstd | 0 | 1 | 0% | 0% | 0% | 0% |
| project::lz4 | 0 | 4 | 25% | 0% | 40% | 18% |
| project::m4 | 0 | 2 | 0% | 0% | 0% | 0% |
| project::ncompress | 0 | 3 | 0% | 0% | 0% | 0% |
| project::openssl | 0 | 4 | 0% | 0% | 0% | 0% |
| project::rsync | 0 | 2 | 25% | 0% | 15% | 15% |
| project::sqlite3 | 0 | 2 | 20% | 0% | 0% | 10% |
| project::tar | 0 | 1 | 0% | 0% | 0% | 0% |
| project::unzip | 0 | 1 | 0% | 0% | 0% | 0% |
| project::wget | 0 | 3 | 0% | 53% | 0% | 7% |
| project::xxhash | 0 | 4 | 0% | 0% | 0% | 0% |
| project::xz-utils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::zip | 0 | 1 | 0% | 0% | 0% | 0% |

## Per-program rows, 80s (n 143, malicious 72)


Grouped CV within the session rows (families / projects held out): 

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.819 +/- 0.018 | 0.855 | 0.762 | 0.876 | 0.728 / 0.751 |
| network | 0.729 +/- 0.016 | 0.713 | 0.586 | 0.872 | 0.528 / 0.574 |
| concat | 0.815 +/- 0.025 | 0.881 | 0.762 | 0.868 | 0.671 / 0.732 |
| stacked | 0.806 +/- 0.022 | 0.850 | 0.753 | 0.859 | 0.675 / 0.728 |
| baseline: activity | 0.536 +/- 0.026 | 0.568 | 0.504 | 0.568 | 0.075 / 0.181 |
| baseline: lifetime | 0.686 +/- 0.016 | 0.660 | 0.549 | 0.823 | 0.324 / 0.425 |
| baseline: injection_time | 0.580 +/- 0.014 | 0.601 | 0.589 | 0.572 | 0.069 / 0.179 |
| baseline: batch | 0.491 +/- 0.034 | 0.425 | 0.201 | 0.780 | 0.019 / 0.075 |
| baseline: mode | 0.505 +/- 0.027 | 0.465 | 0.689 | 0.321 | 0.000 / 0.011 |

One-feature baselines on random noise (20 draws, same folds): BA mean 0.476, 95th percentile 0.517, max 0.549

network_minus_host (BA, per fold assignment): -0.090 +/- 0.027, positive in 0 of 10

concat_minus_host (BA, per fold assignment): -0.004 +/- 0.019, positive in 3 of 10

stacked_minus_host (BA, per fold assignment): -0.013 +/- 0.010, positive in 0 of 10

Seen families (stratified folds, rows of one family in training and test):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.882 +/- 0.013 | 0.931 | 0.847 | 0.917 |
| network | 0.772 +/- 0.009 | 0.785 | 0.619 | 0.924 |
| concat | 0.876 +/- 0.021 | 0.954 | 0.850 | 0.901 |
| stacked | 0.879 +/- 0.010 | 0.945 | 0.832 | 0.927 |

Share flagged per group (mean over fold assignments; malicious groups: recall):

| group | label | rows | host | network | concat | stacked |
|---|---|---|---|---|---|---|
| attack::http-flood-2k | 1 | 1 | 0% | 100% | 50% | 0% |
| attack::syn-sink-40k | 1 | 1 | 0% | 100% | 70% | 0% |
| attack::udp-direct-40k | 1 | 1 | 0% | 100% | 0% | 0% |
| family::Akira | 1 | 3 | 93% | 0% | 97% | 93% |
| family::Bert | 1 | 2 | 100% | 0% | 75% | 100% |
| family::BillGates | 1 | 1 | 100% | 100% | 100% | 100% |
| family::BrickStorm | 1 | 4 | 25% | 0% | 12% | 22% |
| family::CatStorm | 1 | 1 | 100% | 0% | 100% | 100% |
| family::Chaos | 1 | 2 | 100% | 100% | 100% | 100% |
| family::ChinaZ | 1 | 1 | 100% | 0% | 90% | 100% |
| family::CoinMiner | 1 | 2 | 100% | 100% | 100% | 100% |
| family::DDoSAgent | 1 | 3 | 67% | 33% | 63% | 67% |
| family::DeskRAT | 1 | 3 | 100% | 100% | 100% | 100% |
| family::Dofloo | 1 | 4 | 100% | 100% | 100% | 100% |
| family::Gafgyt | 1 | 4 | 100% | 52% | 100% | 100% |
| family::GetShell | 1 | 2 | 50% | 0% | 45% | 50% |
| family::INC | 1 | 1 | 0% | 0% | 0% | 0% |
| family::Kaiji | 1 | 5 | 100% | 100% | 100% | 100% |
| family::Kaiten | 1 | 3 | 67% | 67% | 67% | 67% |
| family::Katana | 1 | 2 | 100% | 100% | 100% | 100% |
| family::LockBit | 1 | 1 | 10% | 0% | 40% | 10% |
| family::Mirai | 1 | 5 | 78% | 60% | 74% | 74% |
| family::Ngioweb | 1 | 2 | 100% | 70% | 100% | 100% |
| family::Nitrogen | 1 | 1 | 10% | 0% | 0% | 0% |
| family::Prometei | 1 | 2 | 100% | 0% | 100% | 85% |
| family::PromptLock | 1 | 1 | 100% | 100% | 100% | 100% |
| family::Qilin | 1 | 4 | 0% | 0% | 0% | 0% |
| family::RapperBot | 1 | 1 | 100% | 70% | 100% | 100% |
| family::Tsunami | 1 | 7 | 100% | 100% | 100% | 100% |
| family::XorDDoS | 1 | 2 | 100% | 100% | 100% | 100% |
| benign::archive-docs | 0 | 1 | 100% | 0% | 100% | 100% |
| benign::browse-public | 0 | 1 | 0% | 70% | 10% | 0% |
| benign::checkin-public | 0 | 1 | 20% | 100% | 100% | 40% |
| benign::dns-poll | 0 | 1 | 70% | 100% | 90% | 100% |
| benign::download-burst | 0 | 1 | 0% | 20% | 0% | 0% |
| benign::file-search | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_amd64_dynamic-start | 0 | 1 | 40% | 0% | 50% | 40% |
| null::null-native_amd64_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-native_i386_static-start | 0 | 1 | 0% | 0% | 0% | 0% |
| null::null-true | 0 | 1 | 0% | 0% | 0% | 0% |
| project::brotli | 0 | 4 | 25% | 0% | 10% | 22% |
| project::bzip2 | 0 | 3 | 0% | 0% | 0% | 0% |
| project::coreutils | 0 | 3 | 20% | 0% | 27% | 20% |
| project::cpio | 0 | 2 | 0% | 0% | 0% | 0% |
| project::curl | 0 | 4 | 18% | 35% | 10% | 18% |
| project::diffutils | 0 | 3 | 0% | 0% | 0% | 0% |
| project::expat | 0 | 3 | 83% | 0% | 67% | 83% |
| project::git | 0 | 2 | 0% | 0% | 0% | 0% |
| project::gzip | 0 | 2 | 5% | 0% | 5% | 0% |
| project::inetutils | 0 | 4 | 12% | 80% | 18% | 40% |
| project::jq | 0 | 2 | 0% | 0% | 0% | 0% |
| project::libzstd | 0 | 1 | 0% | 0% | 0% | 0% |
| project::lz4 | 0 | 4 | 25% | 0% | 32% | 20% |
| project::m4 | 0 | 2 | 0% | 0% | 0% | 0% |
| project::ncompress | 0 | 3 | 0% | 0% | 0% | 0% |
| project::openssl | 0 | 4 | 0% | 0% | 0% | 0% |
| project::rsync | 0 | 2 | 5% | 0% | 10% | 0% |
| project::sqlite3 | 0 | 2 | 0% | 0% | 0% | 0% |
| project::tar | 0 | 1 | 0% | 0% | 0% | 0% |
| project::unzip | 0 | 1 | 0% | 0% | 0% | 0% |
| project::wget | 0 | 3 | 0% | 53% | 0% | 3% |
| project::xxhash | 0 | 4 | 0% | 0% | 0% | 0% |
| project::xz-utils | 0 | 1 | 0% | 0% | 0% | 0% |
| project::zip | 0 | 1 | 0% | 0% | 0% | 0% |

## Sensitivity: per-program rows, 20 s, including the programs that never started (n 148, malicious 77)

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.792 +/- 0.017 | 0.852 | 0.743 | 0.841 |
| network | 0.683 +/- 0.029 | 0.669 | 0.526 | 0.841 |
| concat | 0.793 +/- 0.025 | 0.869 | 0.777 | 0.810 |
| stacked | 0.774 +/- 0.022 | 0.849 | 0.742 | 0.807 |

## 10-s machine windows (n 340, malicious 72)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.639 +/- 0.025 | 0.859 | 0.328 | 0.949 | 0.326 / 0.469 |
| network | 0.575 +/- 0.021 | 0.748 | 0.163 | 0.988 | 0.342 / 0.456 |
| concat | 0.598 +/- 0.025 | 0.878 | 0.226 | 0.971 | 0.346 / 0.549 |
| stacked | 0.786 +/- 0.025 | 0.869 | 0.771 | 0.800 | 0.390 / 0.550 |
| activity baseline | 0.631 +/- 0.019 | 0.694 | 0.424 | 0.838 | 0.236 / 0.338 |
| position baseline | 0.605 +/- 0.024 | 0.668 | 0.438 | 0.772 | 0.125 / 0.268 |

One-feature baselines on random noise (10 draws): BA mean 0.503, 95th percentile 0.548, max 0.561

network_minus_host (BA, per fold assignment): -0.063 +/- 0.032, positive in 0 of 10

concat_minus_host (BA, per fold assignment): -0.040 +/- 0.021, positive in 0 of 10

stacked_minus_host (BA, per fold assignment): +0.147 +/- 0.025, positive in 10 of 10

Seen families (stratified folds):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.691 +/- 0.017 | 0.888 | 0.422 | 0.960 |
| network | 0.609 +/- 0.014 | 0.753 | 0.224 | 0.994 |
| concat | 0.650 +/- 0.012 | 0.902 | 0.324 | 0.977 |
| stacked | 0.805 +/- 0.014 | 0.895 | 0.790 | 0.821 |

## 30-s machine windows (n 340, malicious 72)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.645 +/- 0.012 | 0.881 | 0.318 | 0.972 | 0.439 / 0.585 |
| network | 0.587 +/- 0.022 | 0.752 | 0.206 | 0.968 | 0.286 / 0.432 |
| concat | 0.652 +/- 0.023 | 0.867 | 0.318 | 0.987 | 0.485 / 0.601 |
| stacked | 0.801 +/- 0.030 | 0.883 | 0.769 | 0.832 | 0.515 / 0.654 |
| activity baseline | 0.511 +/- 0.014 | 0.524 | 0.224 | 0.798 | 0.103 / 0.131 |
| position baseline | 0.631 +/- 0.017 | 0.720 | 0.479 | 0.783 | 0.179 / 0.329 |

One-feature baselines on random noise (10 draws): BA mean 0.503, 95th percentile 0.548, max 0.561

network_minus_host (BA, per fold assignment): -0.058 +/- 0.024, positive in 0 of 10

concat_minus_host (BA, per fold assignment): +0.007 +/- 0.027, positive in 6 of 10

stacked_minus_host (BA, per fold assignment): +0.156 +/- 0.027, positive in 10 of 10

Seen families (stratified folds):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.695 +/- 0.010 | 0.893 | 0.422 | 0.969 |
| network | 0.658 +/- 0.012 | 0.770 | 0.349 | 0.968 |
| concat | 0.726 +/- 0.012 | 0.883 | 0.461 | 0.991 |
| stacked | 0.811 +/- 0.014 | 0.894 | 0.776 | 0.846 |

## 10-s, position-matched (only the window at each session's injection time; added after the interim look) machine windows (n 170, malicious 72)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.582 +/- 0.028 | 0.575 | 0.432 | 0.733 | 0.153 / 0.236 |
| network | 0.618 +/- 0.032 | 0.644 | 0.487 | 0.748 | 0.119 / 0.203 |
| concat | 0.607 +/- 0.032 | 0.653 | 0.447 | 0.767 | 0.156 / 0.251 |
| stacked | 0.572 +/- 0.060 | 0.599 | 0.531 | 0.613 | 0.096 / 0.189 |
| activity baseline | 0.567 +/- 0.023 | 0.584 | 0.528 | 0.607 | 0.163 / 0.214 |
| position baseline | 0.550 +/- 0.029 | 0.546 | 0.521 | 0.580 | 0.040 / 0.115 |

One-feature baselines on random noise (10 draws): BA mean 0.464, 95th percentile 0.510, max 0.524

network_minus_host (BA, per fold assignment): +0.035 +/- 0.038, positive in 9 of 10

concat_minus_host (BA, per fold assignment): +0.025 +/- 0.032, positive in 8 of 10

stacked_minus_host (BA, per fold assignment): -0.010 +/- 0.074, positive in 5 of 10

Seen families (stratified folds):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.660 +/- 0.022 | 0.710 | 0.493 | 0.828 |
| network | 0.642 +/- 0.015 | 0.700 | 0.518 | 0.766 |
| concat | 0.676 +/- 0.012 | 0.756 | 0.507 | 0.845 |
| stacked | 0.675 +/- 0.020 | 0.737 | 0.625 | 0.724 |

## 30-s, position-matched (added after the interim look) machine windows (n 170, malicious 72)

| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |
|---|---|---|---|---|---|
| host | 0.593 +/- 0.027 | 0.615 | 0.406 | 0.780 | 0.235 / 0.287 |
| network | 0.581 +/- 0.052 | 0.596 | 0.410 | 0.752 | 0.110 / 0.210 |
| concat | 0.614 +/- 0.031 | 0.633 | 0.417 | 0.811 | 0.190 / 0.312 |
| stacked | 0.586 +/- 0.058 | 0.608 | 0.489 | 0.683 | 0.185 / 0.275 |
| activity baseline | 0.468 +/- 0.013 | 0.491 | 0.383 | 0.553 | 0.093 / 0.140 |
| position baseline | 0.550 +/- 0.029 | 0.546 | 0.521 | 0.580 | 0.040 / 0.115 |

One-feature baselines on random noise (10 draws): BA mean 0.464, 95th percentile 0.510, max 0.524

network_minus_host (BA, per fold assignment): -0.012 +/- 0.061, positive in 4 of 10

concat_minus_host (BA, per fold assignment): +0.021 +/- 0.033, positive in 6 of 10

stacked_minus_host (BA, per fold assignment): -0.007 +/- 0.048, positive in 5 of 10

Seen families (stratified folds):

| detector | BA mean +/- sd | AUC | recall | specificity |
|---|---|---|---|---|
| host | 0.671 +/- 0.020 | 0.747 | 0.494 | 0.847 |
| network | 0.648 +/- 0.022 | 0.694 | 0.510 | 0.786 |
| concat | 0.709 +/- 0.021 | 0.762 | 0.544 | 0.874 |
| stacked | 0.725 +/- 0.028 | 0.768 | 0.660 | 0.790 |

## Lab cue (a connection left unanswered)

BA 0.507, recall 0.014, specificity 1.000; flagged by kind {"attack": 0.3333333333333333, "benign": 0.0, "malware": 0.0, "null": 0.0}
