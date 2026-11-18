<!-- pairs -->
| mode | HTTP row | HTTPS row | curl SHA-256 (16) | runs (HTTP + HTTPS) | tshark |
|---|---|---|---|---|---|
| amd64_dynamic | `curl-net-amd64_dynamic` (row 87) | `curl-net-amd64_dynamic-2` (row 88) | `7dc07fd77b104e65` | 2 + 2 | HTTP cleartext / TLS1.3 |
| amd64_static | `curl-net-amd64_static` (row 126) | `curl-net-amd64_static-2` (row 127) | `d912f1862f9f39ca` | 5 + 5 | HTTP cleartext / TLS1.3 |
| i386_static | `curl-net-i386_static` (row 182) | `curl-net-i386_static-2` (row 183) | `ab7a2b716bea34fa` | 5 + 5 | HTTP cleartext / TLS1.3 |

<!-- wire -->
|  | amd64_dynamic | amd64_static | i386_static |
|---|---|---|---|
| packets (switch-counted) | 12 → 16 (+33%) | 12 → 16 (+33%) | 12 → 18 (+50%) |
| Ethernet bytes | 1288 → 4183 (+225%) | 1288 → 4183 (+225%) | 1288 → 4309 (+235%) |
| client payload bytes | 72 → 715 (+893%) | 72 → 715 (+893%) | 72 → 715 (+893%) |
| server payload bytes | 408 → 2408 (+490%) | 408 → 2408 (+490%) | 408 → 2408 (+490%) |
| TLS records (4 cleartext + 12 encrypted) | 0 → 16 | 0 → 16 | 0 → 16 |
| RST from server | 0 → 2 | 0 → 2 | 0 → 3 |
| FIN segments | 2 (same) | 2 (same) | 2 → 3 (+50%) |

<!-- net -->
| switch signal | amd64_dynamic | amd64_static | i386_static |
|---|---|---|---|
| `net_flow_count_seen` | 1 (same) | 1 (same) | 1 (same) |
| `net_pkts_total_delta` | 12 → 16 (+33%) | 12 → 16 (+33%); HTTPS repeats 14–16 | 12 → 18 (+50%); HTTPS repeats 16–18 |
| `net_bytes_total_delta` | 1288 → 4183 (+225%) | 1288 → 4183 (+225%); HTTPS repeats 4057–4183 | 1288 → 4309 (+235%); HTTPS repeats 4183–4309 |
| `net_pkts_ab_delta` | 7 → 9 (+29%) | 7 → 9 (+29%); HTTPS repeats 8–9 | 7 → 10 (+43%); HTTPS repeats 9–10 |
| `net_bytes_ab_delta` | 542 → 1317 (+143%) | 542 → 1317 (+143%); HTTPS repeats 1251–1317 | 542 → 1383 (+155%); HTTPS repeats 1317–1383 |
| `net_pkts_ba_delta` | 5 → 7 (+40%) | 5 → 7 (+40%); HTTPS repeats 6–7 | 5 → 8 (+60%); HTTPS repeats 7–8 |
| `net_bytes_ba_delta` | 746 → 2866 (+284%) | 746 → 2866 (+284%); HTTPS repeats 2806–2866 | 746 → 2926 (+292%); HTTPS repeats 2866–2932 |
| `net_min_len_mean` | 66 → 60 (-9%) | 66 → 60 (-9%) | 66 → 60 (-9%) |
| `net_max_len_mean` | 324 → 1487 (+359%) | 324 → 1487 (+359%) | 324 → 1487 (+359%) |
| `net_min_len_min` | 66 → 60 (-9%) | 66 → 60 (-9%) | 66 → 60 (-9%) |
| `net_max_len_max` | 324 → 1487 (+359%) | 324 → 1487 (+359%) | 324 → 1487 (+359%) |
| `net_avg_pkt_size_delta` | 107 → 261 (+144%) | 107 → 261 (+144%); HTTPS repeats 261–290 | 107 → 239 (+123%); HTTPS repeats 239–261 |
| `net_avg_pkt_size_ab_delta` | 77.4 → 146 (+89%) | 77.4 → 146 (+89%); HTTPS repeats 146–156 | 77.4 → 138 (+79%); HTTPS repeats 138–146 |
| `net_avg_pkt_size_ba_delta` | 149 → 409 (+174%) | 149 → 409 (+174%); HTTPS repeats 409–468 | 149 → 366 (+145%); HTTPS repeats 366–409 |
| `net_flow_duration_mean` | 0.0122 → 0.0341 (+180%); HTTP repeats 0.0112–0.0122; HTTPS repeats 0.0341–0.0366 | 0.0103 → 0.0378 (+267%); HTTP repeats 0.0103–0.0113; HTTPS repeats 0.0339–0.0381 | 0.0114 → 0.0356 (+212%); HTTP repeats 0.0099–0.0115; HTTPS repeats 0.034–0.0382 |
| `net_flow_duration_max` | 0.0122 → 0.0341 (+180%); HTTP repeats 0.0112–0.0122; HTTPS repeats 0.0341–0.0366 | 0.0103 → 0.0378 (+267%); HTTP repeats 0.0103–0.0113; HTTPS repeats 0.0339–0.0381 | 0.0114 → 0.0356 (+212%); HTTP repeats 0.0099–0.0115; HTTPS repeats 0.034–0.0382 |
| `net_bytes_per_sec_delta` | 2576 → 8366 (+225%) | 2576 → 8366 (+225%); HTTPS repeats 8114–8366 | 2576 → 8618 (+235%); HTTPS repeats 8366–8618 |
| `net_pkts_per_sec_delta` | 24 → 32 (+33%) | 24 → 32 (+33%); HTTPS repeats 28–32 | 24 → 36 (+50%); HTTPS repeats 32–36 |
| `net_down_up_ratio_delta` | 1.38 → 2.18 (+58%) | 1.38 → 2.18 (+58%); HTTPS repeats 2.18–2.24 | 1.38 → 2.12 (+54%); HTTPS repeats 2.12–2.23 |
| `net_ab_ratio_pkt_delta` | 0.583 → 0.562 (-4%) | 0.583 → 0.562 (-4%); HTTPS repeats 0.562–0.571 | 0.583 → 0.556 (-5%); HTTPS repeats 0.529–0.562 |
| `net_ba_ratio_pkt_delta` | 0.417 → 0.438 (+5%) | 0.417 → 0.438 (+5%); HTTPS repeats 0.429–0.438 | 0.417 → 0.444 (+7%); HTTPS repeats 0.438–0.471 |
| `net_ab_ratio_byte_delta` | 0.421 → 0.315 (-25%) | 0.421 → 0.315 (-25%); HTTPS repeats 0.308–0.315 | 0.421 → 0.321 (-24%); HTTPS repeats 0.31–0.321 |
| `net_ba_ratio_byte_delta` | 0.579 → 0.685 (+18%) | 0.579 → 0.685 (+18%); HTTPS repeats 0.685–0.692 | 0.579 → 0.679 (+17%); HTTPS repeats 0.679–0.69 |
| `net_syn_delta` | 2 (same) | 2 (same) | 2 (same) |
| `net_ack_delta` | 11 → 13 (+18%) | 11 → 13 (+18%); HTTPS repeats 12–13 | 11 → 14 (+27%); HTTPS repeats 13–14 |
| `net_rst_delta` | 0 → 2 | 0 → 2; HTTPS repeats 1–2 | 0 → 3; HTTPS repeats 2–3 |
| `net_flows_with_ab` | 1 (same) | 1 (same) | 1 (same) |
| `net_flows_with_ba` | 1 (same) | 1 (same) | 1 (same) |
| `net_dir_valid_count` | 1 (same) | 1 (same) | 1 (same) |

<!-- host -->
| host signal (max over windows; sum where marked) | amd64_dynamic | amd64_static | i386_static |
|---|---|---|---|
| `host_total_syscalls_total` (sum) | 352 → 405 (+15%) | 349 → 696 (+99%) | 338 → 892 (+164%); HTTPS repeats 887–892 |
| `host_unique_syscalls_mean` | 49 → 47 (-4%) | 55 → 54 (-2%) | 62 → 64 (+3%) |
| `host_unique_syscalls_max` | 49 → 47 (-4%) | 55 → 54 (-2%) | 62 → 64 (+3%) |
| `host_entropy_mean` | 4.13 → 4.19 (+1%) | 4 → 3.39 (-15%) | 4.51 → 3.42 (-24%); HTTPS repeats 3.41–3.42 |
| `host_entropy_max` | 4.13 → 4.19 (+1%) | 4 → 3.39 (-15%) | 4.51 → 3.42 (-24%); HTTPS repeats 3.41–3.42 |
| `host_avg_run_length_mean` | 1.82 → 1.89 (+4%) | 1.91 → 1.83 (-4%) | 1.86 → 1.4 (-25%); HTTPS repeats 1.4–1.4 |
| `host_avg_run_length_max` | 1.82 → 1.89 (+4%) | 1.91 → 1.83 (-4%) | 1.86 → 1.4 (-25%); HTTPS repeats 1.4–1.4 |
| `host_max_run_length_mean` | 54 (same) | 54 → 56 (+4%) | 54 (same) |
| `host_max_run_length_max` | 54 (same) | 54 → 56 (+4%) | 54 (same) |
| `host_transition_count_total` (sum) | 192 → 213 (+11%) | 182 → 380 (+109%) | 181 → 638 (+252%); HTTPS repeats 634–638 |
| `host_rare_syscall_ratio_mean` | 0.0426 → 0.0321 (-25%) | 0.0716 → 0.033 (-54%) | 0.0858 → 0.0325 (-62%); HTTPS repeats 0.0325–0.0327 |
| `host_rare_syscall_ratio_max` | 0.0426 → 0.0321 (-25%) | 0.0716 → 0.033 (-54%) | 0.0858 → 0.0325 (-62%); HTTPS repeats 0.0325–0.0327 |
| `host_first50_unique_mean` | 5 (same) | 5 (same) | 5 (same) |
| `host_first50_unique_max` | 5 (same) | 5 (same) | 5 (same) |
| `host_first100_unique_mean` | 15 (same) | 15 (same) | 15 (same) |
| `host_first100_unique_max` | 15 (same) | 15 (same) | 15 (same) |
| `host_top_syscall_freq_mean` | 0.315 → 0.274 (-13%) | 0.327 → 0.279 (-15%) | 0.237 → 0.298 (+26%); HTTPS repeats 0.298–0.3 |
| `host_top_syscall_freq_max` | 0.315 → 0.274 (-13%) | 0.327 → 0.279 (-15%) | 0.237 → 0.298 (+26%); HTTPS repeats 0.298–0.3 |

<!-- sys -->
| mode | curl system calls | largest changes (HTTPS − HTTP) |
|---|---|---|
| amd64_dynamic | 174 → 227 | read +24, getpid +14, brk +5, poll +4, write +4, futex +3 |
| amd64_static | 171 → 518 | mmap +148, munmap +148, read +24, getpid +14, poll +4, write +4 |
| i386_static | 160 → 714 | mmap2 +239, munmap +238, madvise +26, read +24, getpid +14, rt_sigprocmask +4 |

<!-- con -->
| contrast | mode | runs | net changed / separated | net D | net D repeats | net perm p | host changed / separated | host D | host D repeats |
|---|---|---|---|---|---|---|---|---|---|
| **transport** | amd64_dynamic | 2/2 | 97 / 97 | 3.91 | 0.00069 | - | 48 / 48 | 0.54 | 0 |
| **transport** | amd64_static | 5/5 | 97 / 97 | 4.23 | 0.25 | 0.0079 | 56 / 56 | 0.95 | 0 |
| **transport** | i386_static | 5/5 | 97 / 97 | 3.68 | 0.2 | 0.0079 | 48 / 48 | 1.66 | 0.0037 |
| options | amd64_dynamic | 2/3 | 24 / 0 | 0.00 | 0.00052 | - | 50 / 44 | 1.71 | 0.013 |
| program | amd64_dynamic | 2/2 | 40 / 40 | 0.20 | 0.00033 | - | 56 / 56 | 1.48 | 0 |
| program | amd64_static | 5/5 | 40 / 32 | 0.20 | 0.00038 | 0.0079 | 56 / 56 | 1.88 | 0 |
| program | i386_static | 5/5 | 40 / 32 | 0.20 | 0.00035 | 0.0079 | 56 / 56 | 1.52 | 0 |
| request:post | amd64_static | 5/3 | 55 / 40 | 0.31 | 0.00021 | 0.018 | 44 / 0 | 0.01 | 0.0045 |
| request:post | i386_static | 5/3 | 55 / 40 | 0.31 | 0.00036 | 0.018 | 16 / 0 | 0.00 | 0 |
| request:headers | amd64_static | 5/3 | 55 / 32 | 0.03 | 0.00022 | 0.018 | 44 / 40 | 0.11 | 0 |
| request:headers | i386_static | 5/3 | 55 / 32 | 0.03 | 0.00032 | 0.018 | 44 / 40 | 0.09 | 0 |
| request:index | i386_static | 5/3 | 55 / 32 | 0.04 | 0.00037 | 0.018 | 16 / 0 | 0.00 | 0 |
| url | amd64_dynamic | 2/2 | 40 / 40 | 0.01 | 0.00037 | - | 0 / 0 | 0.00 | 0 |
| url | amd64_static | 5/5 | 40 / 32 | 0.01 | 0.00039 | 0.0079 | 0 / 0 | 0.00 | 0 |
| url | i386_static | 5/5 | 40 / 32 | 0.01 | 0.00049 | 0.0079 | 0 / 0 | 0.00 | 0 |
| tls-option | amd64_dynamic | 2/2 | 64 / 36 | 0.54 | 0.18 | - | 28 / 28 | 0.02 | 0 |
| tls-option | amd64_static | 5/5 | 72 / 20 | 0.45 | 0.24 | 0.0079 | 40 / 40 | 0.02 | 0 |
| tls-option | i386_static | 5/3 | 82 / 28 | 0.38 | 0.59 | 0.48 | 44 / 8 | 0.01 | 0.014 |
| port (telnet 58da93ec) | amd64_static | 2/2 | 65 / 65 | 0.64 | 0.00073 | - | 0 / 0 | 0.00 | 0 |
| port (telnet adcf3ee0) | amd64_static | 2/2 | 65 / 65 | 0.64 | 0.00044 | - | 0 / 0 | 0.00 | 0 |
| port (telnet e2518af2) | i386_static | 3/3 | 65 / 65 | 0.64 | 0.00063 | 0.1 | 0 / 0 | 0.00 | 0 |

<!-- det -->
| mode | detector | flag rate HTTP → HTTPS | mean p HTTP → HTTPS | decision changes, HTTP vs HTTPS pairs | decision changes, repeat pairs |
|---|---|---|---|---|---|
| amd64_dynamic | host | 0.70 → 0.70 | 0.609 → 0.537 | 8/40 | 0/20 |
| amd64_dynamic | network | 0.00 → 0.00 | 0.079 → 0.022 | 0/40 | 0/20 |
| amd64_dynamic | concat | 0.20 → 0.10 | 0.380 → 0.280 | 4/40 | 0/20 |
| amd64_dynamic | stacked | 0.30 → 0.20 | 0.341 → 0.284 | 4/40 | 0/20 |
| amd64_static | host | 0.50 → 0.10 | 0.465 → 0.231 | 100/250 | 0/200 |
| amd64_static | network | 0.00 → 0.00 | 0.079 → 0.021 | 0/250 | 0/200 |
| amd64_static | concat | 0.00 → 0.10 | 0.304 → 0.147 | 25/250 | 0/200 |
| amd64_static | stacked | 0.00 → 0.00 | 0.262 → 0.146 | 0/250 | 0/200 |
| i386_static | host | 0.30 → 0.00 | 0.411 → 0.222 | 75/250 | 0/200 |
| i386_static | network | 0.00 → 0.00 | 0.079 → 0.023 | 0/250 | 0/200 |
| i386_static | concat | 0.10 → 0.00 | 0.305 → 0.128 | 25/250 | 0/200 |
| i386_static | stacked | 0.10 → 0.00 | 0.243 → 0.134 | 25/250 | 0/200 |

<!-- flips -->
| pairs of runs | host | network | concat | stacked |
|---|---|---|---|---|
| **HTTP → HTTPS (transport)** | **183/540** | **0/540** | **54/540** | **29/540** |
| repeats of one task (all transport repeats) | 0/420 | 0/420 | 0/420 | 0/420 |
| curl → wget (same GET /) | 195/540 | 0/540 | 29/540 | 33/540 |
| curl -s → progress meter on | 42/60 | 0/60 | 12/60 | 18/60 |
| GET / → GET /headers -D | 45/300 | 0/300 | 0/300 | 0/300 |
| GET / → POST /submit | 10/300 | 0/300 | 0/300 | 0/300 |
| wget GET / → GET /data | 0/540 | 0/540 | 0/540 | 0/540 |
| openssl SNI → -tls1_3 (TLS both) | 0/440 | 0/440 | 0/440 | 6/440 |

<!-- cls -->
| runs | n | host | network | concat | stacked |
|---|---|---|---|---|---|
| cleartext HTTP tasks (curl, wget) | 63 (9 dataset rows) | 0.32 | 0.00 | 0.08 | 0.04 |
| curl over HTTPS | 12 (3 dataset rows) | 0.16 | 0.00 | 0.06 | 0.03 |
| openssl s_client (TLS) | 25 (5 dataset rows) | 0.13 | 0.00 | 0.06 | 0.04 |
| telnet (TCP connect, no TLS) | 14 (4 dataset rows) | 0.14 | 0.38 | 0.17 | 0.21 |
| *reference: all 105 dataset benign rows (Table V OOF)* | 105 | 0.15 | 0.02 | 0.11 | 0.10 |

<!-- sl -->
| implant | pos | transport (tshark, 5 min) | 20 s: TCP conn / TLS handshakes / HTTP requests | 20 s: packets / bytes | 5 min: TCP conn / TLS / HTTP | 5 min: packets / bytes | host calls 20 s / 5 min | stray WG pkts 20 s / 5 min | rc |
|---|---|---|---|---|---|---|---|---|---|
| `lab-http-beacon-a` | 22 | HTTP cleartext; 1 TLS ClientHello without ServerHello | 7 / 0 / 9 | 76 / 15776 | 63 / 0 / 111 | 737 / 169798 | 2631 / 20405 | 0 / 0 | -15 |
| `lab-http-beacon-b` | 24 | HTTP cleartext; 1 TLS ClientHello without ServerHello | 6 / 0 / 9 | 72 / 26223 | 62 / 0 / 110 | 733 / 190019 | 2609 / 20403 | 0 / 0 | -15 |
| `lab-https-beacon-a` | 8 | TLS1.3 | 5 / 5 / 0 | 94 / 36109 | 61 / 61 / 0 | 1183 / 446789 | 2571 / 20713 | 0 / 0 | -15 |
| `lab-https-beacon-b` | 18 | TLS1.3 | 6 / 6 / 0 | 122 / 50557 | 62 / 62 / 0 | 1260 / 465115 | 2716 / 22115 | 4 / 52 | -15 |
| `lab-mtls-beacon-a` | 20 | TLS1.3 | 5 / 5 / 0 | 160 / 36119 | 61 / 61 / 0 | 1981 / 442837 | 2646 / 22800 | 0 / 0 | -15 |
| `lab-mtls-beacon-b` | 6 | TLS1.3 | 5 / 5 / 0 | 152 / 35865 | 61 / 61 / 0 | 1990 / 446803 | 2621 / 24154 | 0 / 0 | -15 |
| `lab-mtls-session-a` | 14 | TLS1.3 | 1 / 1 / 0 | 174 / 24049 | 1 / 1 / 0 | 2038 / 234900 | 2563 / 20595 | 0 / 0 | -15 |
| `lab-mtls-session-b` | 4 | TLS1.3 | 1 / 1 / 0 | 177 / 24351 | 1 / 1 / 0 | 1986 / 231602 | 2752 / 20770 | 0 / 0 | -15 |
| `lab-wg-session-a` | 26 | UDP | 0 / 0 / 0 | 228 / 37496 | 0 / 0 / 0 | 2517 / 413106 | 4055 / 28992 | 0 / 0 | -15 |
| `lab-wg-session-b` | 16 | UDP | 0 / 0 / 0 | 226 / 37348 | 0 / 0 / 0 | 2393 / 398410 | 3747 / 27647 | 0 / 0 | -15 |
| `lab-wg-beacon-a` | 10 | none | 0 / 0 / 0 | 0 / 0 | 0 / 0 / 0 | 0 / 0 | 795 / 795 | 0 / 0 | 2 |
| `lab-wg-beacon-b` | 12 | none | 0 / 0 / 0 | 0 / 0 | 0 / 0 / 0 | 0 / 0 | 815 / 815 | 0 / 0 | 2 |

<!-- stray -->
| pos | run | kind | stray WG packets, first 20 s | 5 min |
|---|---|---|---|---|
| 17 | `native_amd64_dynamic-git-git-hold-ip` | benign | 5 | 57 |
| 18 | `lab-https-beacon-b` | https-beacon | 4 | 52 |
| 19 | `native_amd64_dynamic-rsync-rsync-timeout60` | benign | 2 | 20 |
| 27 | `native_amd64_dynamic-curl-curl-oneshot-host` | benign | 5 | 57 |

<!-- bsig -->
| signal | 20 s HTTP | 20 s HTTPS | 20 s mTLS | 5 min HTTP | 5 min HTTPS | 5 min mTLS |
|---|---|---|---|---|---|---|
| packets (`net_pkts_total_delta`, sum) | 76 / 72 | 94 / 118 | 152 / 160 | 737 / 733 | 1183 / 1208 | 1990 / 1981 |
| bytes (`net_bytes_total_delta`, sum) | 15776 / 26223 | 36109 / 49797 | 35865 / 36119 | 169798 / 190019 | 446789 / 455235 | 446803 / 442837 |
| bytes guest → server (`net_bytes_ab_delta`, sum) | 10714 / 21315 | 18434 / 24382 | 20218 / 19944 | 101517 / 123066 | 211541 / 223328 | 248175 / 242170 |
| bytes server → guest (`net_bytes_ba_delta`, sum) | 5062 / 4908 | 17675 / 25415 | 15647 / 16175 | 68281 / 66953 | 235248 / 231907 | 198628 / 200667 |
| SYN (≈ 2 per connection) (`net_syn_delta`, sum) | 14 / 12 | 10 / 12 | 10 / 10 | 126 / 124 | 122 / 124 | 122 / 122 |
| RST (`net_rst_delta`, sum) | 0 / 0 | 9 / 12 | 11 / 10 | 0 / 0 | 125 / 129 | 123 / 124 |
| flow-windows (flows × windows active) (`net_flow_count_seen`, sum) | 28 / 24 | 20 / 24 | 30 / 30 | 252 / 248 | 244 / 248 | 366 / 366 |
| longest flow, s (`net_flow_duration_max`, max) | 0.013 / 0.01 | 0.012 / 0.013 | 1.022 / 1.014 | 0.052 / 0.023 | 0.112 / 0.035 | 1.03 / 1.032 |
| largest frame, B (`net_max_len_max`, max) | 1561 / 4630 | 2415 / 2566 | 2054 / 2054 | 4967 / 4944 | 5365 / 5392 | 2054 / 2054 |
| host system calls (`host_total_syscalls_total`, sum) | 2631 / 2609 | 2571 / 2716 | 2621 / 2646 | 20405 / 20403 | 20713 / 22115 | 24154 / 22800 |
| host entropy (per-window mean) (`host_entropy_mean`, mean) | 0.591 / 0.588 | 0.608 / 0.584 | 0.685 / 0.669 | 0.511 / 0.513 | 0.508 / 0.504 | 0.57 / 0.575 |

<!-- scon -->
| length | role | contrast | net D | net D a/b | net cols > both a/b diffs | host D | host D a/b | host cols > both a/b diffs |
|---|---|---|---|---|---|---|---|---|
| 20s | transport | http-beacon vs https-beacon | 10.9 | 7.9 | 54 | 1.9 | 2.8 | 7 |
| 20s | transport | http-beacon vs mtls-beacon | 13.4 | 5.5 | 114 | 4.2 | 2.6 | 38 |
| 20s | transport | https-beacon vs mtls-beacon | 9.8 | 3.8 | 93 | 4.4 | 2.4 | 38 |
| 20s | reference | mtls-beacon vs mtls-session | 18.5 | 3.3 | 124 | 12.7 | 6.1 | 60 |
| 20s | reference | mtls-session vs wg-session | 12.8 | 4.6 | 107 | 4.9 | 6.9 | 41 |
| 5min | transport | http-beacon vs https-beacon | 9.8 | 2.6 | 78 | 2.5 | 2.5 | 25 |
| 5min | transport | http-beacon vs mtls-beacon | 15.0 | 1.5 | 137 | 4.1 | 3.1 | 53 |
| 5min | transport | https-beacon vs mtls-beacon | 11.1 | 1.4 | 114 | 4.2 | 2.6 | 49 |
| 5min | reference | mtls-beacon vs mtls-session | 20.7 | 0.6 | 135 | 14.6 | 4.4 | 76 |
| 5min | reference | mtls-session vs wg-session | 10.1 | 0.9 | 114 | 5.4 | 3.9 | 79 |

<!-- sdet -->
| variant | implant | host | network | concat | stacked |
|---|---|---|---|---|---|
| as collected | `lab-http-beacon-a` | 0.918 ✓ | 0.240 | 0.578 ✓ | 0.600 ✓ |
| as collected | `lab-http-beacon-b` | 0.920 ✓ | 0.236 | 0.590 ✓ | 0.598 ✓ |
| as collected | `lab-https-beacon-a` | 0.916 ✓ | 0.142 | 0.558 ✓ | 0.511 ✓ |
| as collected | `lab-https-beacon-b` | 0.928 ✓ | 0.644 ✓ | 0.716 ✓ | 0.869 ✓ |
| as collected | `lab-mtls-beacon-a` | 0.908 ✓ | 0.388 | 0.598 ✓ | 0.714 ✓ |
| as collected | `lab-mtls-beacon-b` | 0.906 ✓ | 0.394 | 0.586 ✓ | 0.717 ✓ |
| without stray wireguard | `lab-http-beacon-a` | 0.918 ✓ | 0.240 | 0.578 ✓ | 0.600 ✓ |
| without stray wireguard | `lab-http-beacon-b` | 0.920 ✓ | 0.236 | 0.590 ✓ | 0.598 ✓ |
| without stray wireguard | `lab-https-beacon-a` | 0.916 ✓ | 0.142 | 0.558 ✓ | 0.511 ✓ |
| without stray wireguard | `lab-https-beacon-b` | 0.928 ✓ | 0.154 | 0.556 ✓ | 0.530 ✓ |
| without stray wireguard | `lab-mtls-beacon-a` | 0.908 ✓ | 0.388 | 0.598 ✓ | 0.714 ✓ |
| without stray wireguard | `lab-mtls-beacon-b` | 0.906 ✓ | 0.394 | 0.586 ✓ | 0.717 ✓ |

<!-- sdec -->
| variant | host | network | concat | stacked |
|---|---|---|---|---|
| as collected | 6/6 beacons; 6/12 benign | 1/6 beacons; 5/12 benign | 6/6 beacons; 5/12 benign | 6/6 beacons; 6/12 benign |
| without stray wireguard | 6/6 beacons; 6/12 benign | 0/6 beacons; 2/12 benign | 6/6 beacons; 2/12 benign | 6/6 beacons; 4/12 benign |

<!-- blk -->
| variant | runs | host | network | concat | stacked |
|---|---|---|---|---|---|
| as collected | http-beacon | 1.00 | 0.00 | 1.00 | 0.93 |
| as collected | https-beacon | 1.00 | 0.50 | 1.00 | 0.97 |
| as collected | mtls-beacon | 1.00 | 0.00 | 1.00 | 1.00 |
| as collected | benign | 0.44 | 0.34 | 0.51 | 0.37 |
| without stray wireguard | http-beacon | 1.00 | 0.00 | 1.00 | 0.93 |
| without stray wireguard | https-beacon | 1.00 | 0.00 | 1.00 | 0.90 |
| without stray wireguard | mtls-beacon | 1.00 | 0.00 | 1.00 | 1.00 |
| without stray wireguard | benign | 0.44 | 0.16 | 0.33 | 0.21 |
