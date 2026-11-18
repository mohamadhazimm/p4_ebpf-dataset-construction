# Datasheet: payload-independent host and switch features of Linux malware and benign executions

Structure after Gebru et al., "Datasheets for Datasets" (CACM 2021). Applies to `dataset/features.csv`
(240 rows) and `dataset/rejection_log.csv` of this repository.

## Motivation

**Purpose.** To evaluate detectors that combine two payload-independent views of the same execution: 29
per-flow features a programmable switch can compute (P4, Tofino) and 18 system-call-sequence features an
in-kernel eBPF monitor can compute. Neither view reads packet payloads, so the features do not depend on
whether traffic is encrypted.

**Creator.** Mohamad Hazim, as part of a master's thesis. Collected in October 2026.

## Composition

**Instances.** 240 executions, each of one program in a freshly restored virtual machine, observed for
20 s. One row per execution.

| Category | Rows | Label | What it is |
| --- | ---: | :---: | --- |
| `malware` | 99 | 1 | 28 families, Linux ELF samples from MalwareBazaar (80) and Triage (19) |
| `benign` | 105 | 0 | 36 command-line programs from 24 open-source projects, built from authenticated Ubuntu sources |
| `network_attack` | 15 | 1 | 4 SYN floods and 4 UDP floods (one C generator), 5 Slowloris and 2 GoldenEye runs (two Python tools) |
| `network_benign` | 18 | 0 | bulk uploads and downloads, interactive sessions, periodic beacons and DNS bursts (the same C generator) |
| `null` | 3 | 0 | a program that does nothing |

Total 114 malicious, 126 benign. Execution modes: `amd64_static` 152, `amd64_dynamic` 32, `i386_static` 56.
The main collection was planned matched by mode (18/59/28 malware and benign in `amd64_dynamic`,
`amd64_static`, `i386_static`); after the rejections below the malware count is 14/57/28 and the benign
18/59/28. All network-attack, network-benign and null rows are `amd64_static`.

**Columns.** 15 metadata columns, then 90 host features (`host_*`: 18 signals x 5 summaries) and 145
network features (`net_*`: 29 signals x 5 summaries). Each signal is computed per window of 0.5 s (40
windows); the summaries over the 40 windows are mean, max, sum, standard deviation and the number of
non-zero windows (`active_windows`).

| Metadata column | Meaning |
| --- | --- |
| `execution_id` | SHA-256 of the malware sample, or the workload's name |
| `label` | 1 malicious, 0 benign |
| `category` | see the table above |
| `attack_type` | `syn_flood`, `udp_flood`, `slowloris`, `goldeneye` for network attacks |
| `family` | malware family: the provider's signature or tag, **not independently verified** |
| `project`, `program` | benign source project and program |
| `sha256`, `source` | malware sample hash and where it was obtained (binaries are not distributed) |
| `mode` | ELF class and linkage of the executed program |
| `split` | `train`/`test` of the held-out evaluation (Table IV): 11 malware families and 11 benign projects appear only in `test` |
| `cv_group` | the unit kept together in grouped cross-validation (family, project, attack run, workload kind) |
| `collection_position` | position in the interleaved collection order (main collection only) |
| `return_code` | the program's exit status, or the signal (negative) when it was stopped at 20 s or crashed |
| `syscall_count` | system calls of the program and its children after the program started |

**Not included.** Packet captures and system-call traces (planned for a separate archive), and the
malware binaries (identified by SHA-256 only).

**Recommended splits.** The `split` column for evaluation on unseen families; `cv_group` for grouped
cross-validation. Note that `cv_group` keeps each network-attack *run* separate: runs of one attack tool
then appear on both sides of a fold. To hold attack tools out, group by `attack_type` (see Known biases).

## Collection process

**Environment.** A VirtualBox guest (Ubuntu, headless, with NetworkManager's connectivity check, chrony,
Avahi, cups-browsed, the apt timers and snapd disabled so that the network is silent when nothing runs).
Its only network interface is an internal network shared with a second VM (the Sink) running INetSim and
dnsmasq, which answer HTTP(S), FTP, SMTP, POP3 and DNS with fake responses (every name resolves to the
Sink). There is no route to the Internet.

**Per execution.** Restore the clean snapshot; boot; start the program through a common launcher
(`/bin/bash -c 'exec "$@"'`, standard input from `/dev/null`); observe for exactly 20 s (40 windows of
0.5 s); stop the program; copy the outputs back; restore. The collector (runner schema `2026-10-24.21`,
SHA-256 `4933ff5c...`) records every system call of the program's process tree with bpftrace (raw syscall
tracepoints, 16,384 perf pages per CPU) and captures the guest interface with tcpdump (immediate mode,
64 MiB buffer, 1 s drain); a short TCP probe to the Sink before and after the 40 windows proves the capture
path. Collector settings: `--timeout 20 --window-sec 0.5 --iface enp0s3 --ebpf --fixed-observation
--common-launch-wrapper`.

**Features.** Host features are computed by the collector per window. Network features are computed from
the guest capture by a software model of the switch (`features/switch_model.py`); on the compiled P4
program the 13 count features were identical on 8 replayed captures and byte features 14 B per packet lower
(IPv4 length vs Ethernet frame), as expected (`validation/RESULTS.md`).

**Batches.** The main collection's 219 cases (105 malware, 105 benign, 9 null; 99 malware accepted) ran in
one seed-42 interleaved order on 2026-10-25; its null runs checked that the environment stayed silent. The 15 network attacks ran on 2026-10-26 in their own batch; the 18
network-benign and 3 null rows in three further batches the same day. These later batches are not
interleaved with the main collection.

**Selection.** Malware: at most 10 per family, chosen round-robin across execution modes without regard to
how they behaved; families assigned whole to training or test. Benign: programs chosen per mode, with input
sizes chosen so that their system-call volume overlaps the malware's in every mode.

## Quality gates and rejections

A case is accepted only if all hold: the installed collector's provenance; no reported packet-capture drop
or counter discrepancy and no eBPF event loss; the target program's `exec` observed; the expected ELF mode;
40 finite windows; archive hashes; independently counted capture records equal tcpdump's counters; capture
probes recovered outside the windows; a unique alignment of packets to windows. For null and offline benign
runs, any unexplained packet in a window rejects the run; network-active benign runs must reach the Sink.

`rejection_log.csv` lists the 11 executions that were collected but rejected: 6 of 105 malware (4 whose
`exec` was not observed — the program crashed at start — and 2 heavy samples whose capture or processing
failed) and 5 of 20 network-attack runs (4 with kernel packet drops at high rates, 1 that exceeded the
processing deadline). Nothing was retried or replaced.

## Known biases and limitations

- **Benign coverage.** Benign rows are command-line programs and a traffic generator, not representative
  desktop or server workloads. Programs that stay active for minutes, servers, and interpreters are absent.
- **Network attacks.** Two implementations only. Runs of one tool differ in parameters, so with `cv_group`
  the same tool is in training and test; grouping by attack type, unseen Slowloris runs are missed by every
  detector. The heaviest floods are missing (rejected for packet drops). Slowloris and GoldenEye run in a
  Python interpreter, and no benign row uses Python.
- **Fake services.** The Sink accepts connections but does not speak any malware's command-and-control
  protocol, so command phases are absent; much malware is silent on the network.
- **Batches.** Network attacks and network-benign rows come from separate batches.
- **Labels.** Family labels come from the providers. At least one sample labelled Akira behaves like a
  decryptor. Some malware stops at once without arguments (for example Qilin without its password).
- **Observation.** 20 s per execution. A separate 5-minute study (thesis, Chapter 6) found that detection
  does not improve with longer observation, but behaviour after 20 s is not in this dataset.
- **Artifact baselines.** In the combined cross-validation, a forest on the return code alone reaches
  balanced accuracy 0.66, on lifetime (active windows) 0.59, on activity 0.47 and on mode 0.40; the
  detectors reach 0.76-0.82.

## Uses

Intended: evaluating host-only, network-only and fused detectors under grouped or held-out splits;
studying which payload-independent features separate malware from benign programs. Not intended: claims
about detection rates on real networks or for malware families not represented.

## Distribution and maintenance

Data under CC BY 4.0, code under GPL-2.0 (see `LICENSE` files). Maintained by the author; corrections are
recorded in the repository history.
