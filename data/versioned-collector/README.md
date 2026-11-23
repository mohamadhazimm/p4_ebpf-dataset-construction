# Versioned-collector experiments (2026-10-17 to 2026-11-23)

Every collection, check and offline analysis since the versioned collector was introduced has its own
folder here. Folders are named `<what>-<date or UTC timestamp>`; attempt subfolders are
`<UTC timestamp>/` and are never overwritten, so failed and superseded attempts stay next to the
accepted ones. Frozen drivers pin their inputs by SHA-256 and import their siblings, so files are not
moved between folders: this index is how the work is organised.

## What is in Git and what stays local

Only our own source code (`.py`, `.sh`, `.c`, `.h`, and the one Go program in
`additional-study-review-20261022/transport21/src/`) and Markdown notes and reports are published (see
the `versioned-collector` block in the repository `.gitignore`). These stay on the collection machine:

- malware samples and archives, packet captures, per-run telemetry and VM run outputs;
- the generated `setup_guest.sh` / `setup_pilot.sh` / `setup_static_pilot.sh` scripts, which embed
  the whole guest payload (malware archives included) in base64;
- third-party source, build and sysroot trees used to build the benign programs;
- result JSON/CSV files and logs (their SHA-256 values are recorded in the evidence ledger).

The evidence ledger (the workspace `AGENTS.md`, kept outside this repository) records, for each
folder, the command, runner hash, snapshot, sample IDs, validation and limitations. The `Ledger`
entries below give the title of the ledger section that describes each folder.

## Collector hardening and early cohorts (2026-10-17 to 2026-10-21)

| Folder | What it is | Files in Git |
| --- | --- | ---: |
| [`benign-elf-100-v14-20261020T140000Z`](benign-elf-100-v14-20261020T140000Z/) | Ledger: *Exec-Boundary Neutralization And ELF Benign Collection, 2026-10-20* | 1 |
| [`benign-elf-internet-candidates-20261020`](benign-elf-internet-candidates-20261020/) | docs: [README.md](benign-elf-internet-candidates-20261020/README.md) | 1 |
| [`benign-elf-pilot-v14-20261020T122312Z`](benign-elf-pilot-v14-20261020T122312Z/) | Ledger: *Benign ELF Pilot Retry, 2026-10-20*; docs: [README.md](benign-elf-pilot-v14-20261020T122312Z/README.md) | 2 |
| [`benign-training-pilot23-v14-20261020T064840Z`](benign-training-pilot23-v14-20261020T064840Z/) | Ledger: *Benign 23-Sample Pilot, 2026-10-20* | 1 |
| `benign-training-pilot25-v14-20261020T064501Z` | Ledger: *Benign 23-Sample Pilot, 2026-10-20* | 0 |
| [`cohort-100x100-v18-20261021`](cohort-100x100-v18-20261021/) | Ledger: *Native-Only Redesign And Benign Source Builds, 2026-10-21* | 14 |
| [`cohort-expansion-100x100-v18-20261021`](cohort-expansion-100x100-v18-20261021/) | Ledger: *Actual Expansion Controls Guest Readiness, 2026-10-21*; docs: [README.md](cohort-expansion-100x100-v18-20261021/README.md) | 20 |
| [`ebpf-high-syscall-v7-20261019`](ebpf-high-syscall-v7-20261019/) | Ledger: *High Syscall Perf Buffer A/B, 2026-10-19* | 1 |
| [`ebpf-high-syscall-v8-default-20261019`](ebpf-high-syscall-v8-default-20261019/) | Ledger: *v8 Default Buffer Validation, 2026-10-19*; docs: [README.md](ebpf-high-syscall-v8-default-20261019/README.md) | 2 |
| [`endpoint-fix-20261019T112828Z`](endpoint-fix-20261019T112828Z/) | Ledger: *IPv4 Endpoint Repair And Live Validation, 2026-10-19*; docs: [README.md](endpoint-fix-20261019T112828Z/README.md) | 2 |
| [`endpoint-malware-10-20261019T114344Z`](endpoint-malware-10-20261019T114344Z/) | Ledger: *Fresh Ten-Malware Endpoint QA, 2026-10-19*; docs: [README.md](endpoint-malware-10-20261019T114344Z/README.md) | 2 |
| [`exec-mode-pilot-v16-20261020T204233Z`](exec-mode-pilot-v16-20261020T204233Z/) | Ledger: *Execution-Mode Pilot, Schemas .16–.18, 2026-10-20* | 16 |
| [`exec-success-v15-20261020T202806Z`](exec-success-v15-20261020T202806Z/) | Ledger: *Exec-Success Instrumentation, Schema .15, 2026-10-20* | 3 |
| [`family-loss-monitor-v8-20261019T152933Z`](family-loss-monitor-v8-20261019T152933Z/) | Ledger: *Family-Wide v8 Loss Audit, 2026-10-19*; docs: [README.md](family-loss-monitor-v8-20261019T152933Z/README.md) | 3 |
| `fixcheck-watchpath-20261018` | Watch-path fix check for the host collector (2026-10-18). | 0 |
| [`fresh-batch-qa-20261019T105924Z`](fresh-batch-qa-20261019T105924Z/) | Ledger: *Fresh Four-Case Bash Pilot, 2026-10-19*; docs: [README.md](fresh-batch-qa-20261019T105924Z/README.md) | 2 |
| [`independent-audit-derived-20261020`](independent-audit-derived-20261020/) | Ledger: *Independent Perfect-Score Audit v2, 2026-10-20* | 8 |
| [`lockbit-v8-recheck-20261019T151547Z`](lockbit-v8-recheck-20261019T151547Z/) | Ledger: *LockBit v8 Recheck, 2026-10-19*; docs: [README.md](lockbit-v8-recheck-20261019T151547Z/README.md) | 2 |
| [`loss-mitigation-smoke-20261019`](loss-mitigation-smoke-20261019/) | Ledger: *Capture-Loss Mitigation Smoke, 2026-10-19*; docs: [README.md](loss-mitigation-smoke-20261019/README.md) | 3 |
| [`loss-repeat-malware-20261019T141153Z`](loss-repeat-malware-20261019T141153Z/) | Ledger: *Loss-Flagged Malware Repeat, 2026-10-19*; docs: [README.md](loss-repeat-malware-20261019T141153Z/README.md) | 2 |
| [`malware-native-dynamic-v18-20261021`](malware-native-dynamic-v18-20261021/) | Ledger: *Matched Native-Dynamic Malware Pilot, 2026-10-21* | 2 |
| [`malware-native-static-v18-20261021`](malware-native-static-v18-20261021/) | Ledger: *Matched Native-Static Malware Pilot, 2026-10-21* | 4 |
| [`malware-pcap-counter-qa-v12-20261019T203011Z`](malware-pcap-counter-qa-v12-20261019T203011Z/) | Ledger: *Malware PCAP Counter QA, 2026-10-19*; docs: [README.md](malware-pcap-counter-qa-v12-20261019T203011Z/README.md) | 2 |
| [`overnight-qa-v12-20261019T214633Z`](overnight-qa-v12-20261019T214633Z/) | Ledger: *Overnight Sensor QA, 2026-10-19*; docs: [README.md](overnight-qa-v12-20261019T214633Z/README.md) | 5 |
| `paired-elf-watchpath-pilot-20261018` | Paired benign-ELF / malware pilot with watch paths, first version (2026-10-18). | 0 |
| `paired-elf-watchpath-pilot-v2-20261018` | Paired ELF watch-path pilot, version 2 (2026-10-18). | 0 |
| `paired-elf-watchpath-pilot-v3-20261018` | Paired ELF watch-path pilot, version 3 (2026-10-18). | 0 |
| `paired-elf-watchpath-pilot-v3-lockbit-retry-20261018` | Paired ELF pilot v3, LockBit retry (2026-10-18). | 0 |
| `paired-elf-watchpath-pilot-v4-20261018` | Ledger: *Overnight Sensor QA, 2026-10-19* | 0 |
| [`pcap-backend-inventory-v10-20261019T193426Z`](pcap-backend-inventory-v10-20261019T193426Z/) | Ledger: *PCAP Counter Gap Safeguard, 2026-10-19* | 1 |
| `pcap-counter-drain-v10-2000ms-20261019T190534Z` | Ledger: *PCAP Counter Gap Safeguard, 2026-10-19* | 0 |
| [`pcap-counter-drain-v10-default-20261019T190242Z`](pcap-counter-drain-v10-default-20261019T190242Z/) | Ledger: *PCAP Counter Gap Safeguard, 2026-10-19*; docs: [README.md](pcap-counter-drain-v10-default-20261019T190242Z/README.md) | 1 |
| [`pcap-counter-drain-v9-20261019T185624Z`](pcap-counter-drain-v9-20261019T185624Z/) | docs: [README.md](pcap-counter-drain-v9-20261019T185624Z/README.md) | 1 |
| [`pcap-filter-order-v12-20261019T205926Z`](pcap-filter-order-v12-20261019T205926Z/) | Ledger: *Filtered PCAP Position Diagnostic, 2026-10-19*; docs: [README.md](pcap-filter-order-v12-20261019T205926Z/README.md) | 3 |
| [`pcap-filtered-repeat-v12-20261019T211458Z`](pcap-filtered-repeat-v12-20261019T211458Z/) | Ledger: *Filtered PCAP Repeat, 2026-10-19*; docs: [README.md](pcap-filtered-repeat-v12-20261019T211458Z/README.md) | 3 |
| [`pcap-immediate-mode-v13-20261020T051431Z`](pcap-immediate-mode-v13-20261020T051431Z/) | Ledger: *Immediate-Mode Sequence Trial, 2026-10-20* | 1 |
| [`pcap-immediate-mode-v13-buffer64-20261020T055909Z`](pcap-immediate-mode-v13-buffer64-20261020T055909Z/) | Ledger: *Immediate-Mode 64-MiB Trial, 2026-10-20* | 1 |
| `pcap-immediate-mode-v14-default-buffer64-20261020T063145Z` | Ledger: *Schema .14 Default-Buffer Validation, 2026-10-20* | 0 |
| [`pcap-interface-sequence-v10-20261019T193900Z`](pcap-interface-sequence-v10-20261019T193900Z/) | Ledger: *PCAP Counter Gap Safeguard, 2026-10-19* | 1 |
| [`pcap-interface-sequence-v11-20261019T194156Z`](pcap-interface-sequence-v11-20261019T194156Z/) | Ledger: *PCAP Counter Gap Safeguard, 2026-10-19*; docs: [README.md](pcap-interface-sequence-v11-20261019T194156Z/README.md) | 2 |
| [`pcap-lifecycle-diagnostics-v12-20261019T200711Z`](pcap-lifecycle-diagnostics-v12-20261019T200711Z/) | Ledger: *PCAP Lifecycle Diagnostic Instrumentation, 2026-10-19*; docs: [README.md](pcap-lifecycle-diagnostics-v12-20261019T200711Z/README.md) | 2 |
| [`pcap-sequence-v10-20261019T191430Z`](pcap-sequence-v10-20261019T191430Z/) | Ledger: *PCAP Counter Gap Safeguard, 2026-10-19*; docs: [README.md](pcap-sequence-v10-20261019T191430Z/README.md) | 3 |
| [`runner-v4-family-smoke-20261019T130151Z`](runner-v4-family-smoke-20261019T130151Z/) | Ledger: *Runner v4 Family Coverage Smoke, 2026-10-19*; docs: [README.md](runner-v4-family-smoke-20261019T130151Z/README.md) | 2 |
| [`scale-100x100-v14-20261020T072500Z`](scale-100x100-v14-20261020T072500Z/) | Ledger: *100x100 Cohort Completion, 2026-10-20* | 10 |
| `telemetry-2026-10-17.2-20261017T220355Z` | Versioned cohort run, runner schema 2026-10-17.2 (superseded; kept as the audit trail of the confound findings). | 0 |
| `telemetry-2026-10-17.2-20261017T220501Z` | Versioned cohort run, runner schema 2026-10-17.2 (superseded). | 0 |
| `telemetry-2026-10-17.2-20261017T220800Z` | Versioned cohort run, runner schema 2026-10-17.2 (superseded). | 0 |
| [`telemetry-2026-10-17.2-20261017T220948Z`](telemetry-2026-10-17.2-20261017T220948Z/) | Versioned 535/323 malware cohort, runner schema 2026-10-17.2, with the corrected-P4 rebuild (superseded). | 2 |
| `telemetry-2026-10-18.1-20261018T161243Z` | Versioned cohort attempt, runner schema 2026-10-18.1 (superseded). | 0 |
| `telemetry-2026-10-18.1-20261018T161354Z` | Ledger: *Bash Dataset Retrieval Check, 2026-10-19* | 0 |
| `telemetry-2026-10-18.1-pilot40-20261018` | 40-sample pilot, runner schema 2026-10-18.1. | 0 |
| `telemetry-2026-10-18.1-pilot40-fixed-20261018` | 40-sample pilot after the first host-collector fix. | 0 |
| `telemetry-2026-10-18.1-pilot40-nativeargs-20261018` | 40-sample pilot with native benign arguments. | 0 |
| [`telemetry-2026-10-18.1-pilot40-nativenames-20261018`](telemetry-2026-10-18.1-pilot40-nativenames-20261018/) | 40-sample pilot with native program names (corrected host collector).; docs: [README.md](telemetry-2026-10-18.1-pilot40-nativenames-20261018/README.md) | 1 |
| `telemetry-2026-10-18.2-openat-cmp-20261018` | openat path-capture comparison, runner schema 2026-10-18.2. | 0 |
| `telemetry-2026-10-18.2-openat-grouped-362-20261018` | 362-sample grouped recollection with openat paths, runner schema 2026-10-18.2. | 0 |
| `telemetry-2026-10-18.2-openat-recollection40-20261018` | 40-sample openat recollection, runner schema 2026-10-18.2. | 0 |
| `tls-smoke-20261019` | Ledger: *Bash Dataset Retrieval Check, 2026-10-19* | 0 |
| [`zero-feature-trigger-20261019`](zero-feature-trigger-20261019/) | Ledger: *Benign Zero-Feature Trigger Probe, 2026-10-19*; docs: [README.md](zero-feature-trigger-20261019/README.md) | 4 |

## Study review, revision 5, external datasets, observation length, committee analyses and the session lab (2026-10-22 to 2026-11-17)

All under [`additional-study-review-20261022/`](additional-study-review-20261022/). Its top level holds
the drivers and analysis scripts; each subfolder holds the attempts of one experiment.

| Folder | What it is | Files in Git |
| --- | --- | ---: |
| `additional-study-review-20261022/__pycache__` | Ledger: *Disk Cleanup And open-p4studio Setup Started, 2026-11-04* | 0 |
| `additional-study-review-20261022/additional-benign-builds` | Ledger: *Additional Independent Benign Sources, Builds And Host Tasks, 2026-10-23* | 0 |
| [`additional-study-review-20261022/additional-benign-guest-readiness`](additional-study-review-20261022/additional-benign-guest-readiness/) | Ledger: *Additional Benign Guest Gate And Sixteen-Unit Assessment, 2026-10-23* | 2 |
| `additional-study-review-20261022/additional-benign-preparation` | Ledger: *Additional Independent Benign Sources, Builds And Host Tasks, 2026-10-23* | 0 |
| [`additional-study-review-20261022/additional-benign-workloads`](additional-study-review-20261022/additional-benign-workloads/) | Ledger: *Additional Independent Benign Sources, Builds And Host Tasks, 2026-10-23* | 1 |
| `additional-study-review-20261022/amd64-network-builds` | Ledger: *amd64-static Sink Clients Built; Benign Bound; Network Share ~a Third, 2026-10-24* | 0 |
| `additional-study-review-20261022/attempts` | Ledger: *IPv4 Endpoint Repair And Live Validation, 2026-10-19* | 0 |
| `additional-study-review-20261022/attribution-live-capability` | Ledger: *Actual I386 Failure And Separate V6 Gate Prepared, 2026-10-23* | 0 |
| [`additional-study-review-20261022/attribution-pilot`](additional-study-review-20261022/attribution-pilot/) | Ledger: *Benign Attribution Pilot Authorized, 2026-10-22* | 1 |
| [`additional-study-review-20261022/attribution-v1`](additional-study-review-20261022/attribution-v1/) | Ledger: *Benign Source Builds And Attribution Candidate, 2026-10-22* | 4 |
| [`additional-study-review-20261022/attribution-v2`](additional-study-review-20261022/attribution-v2/) | Ledger: *Remediation Guest Results And Static Matching, 2026-10-22* | 2 |
| [`additional-study-review-20261022/attribution-v3`](additional-study-review-20261022/attribution-v3/) | Ledger: *Actual I386 Failure And Separate V6 Gate Prepared, 2026-10-23* | 2 |
| [`additional-study-review-20261022/autoscan-viability`](additional-study-review-20261022/autoscan-viability/) | Ledger: *15-Sample Autoscan Viability De-Risk: 0/15 Floods (combined 0/44), 2026-10-26* | 4 |
| `additional-study-review-20261022/benchmark-quiet-policy-proposals` | Ledger: *Benchmark Quiet Policy Developed Locally, 2026-10-23* | 0 |
| `additional-study-review-20261022/benign-bursty-5min` | Ledger: *5-Min Benign Validation Gap (top/lowrate Never Ran) + Timing Control + Bursty/Short Benign Collection, 2026-11-07* | 0 |
| `additional-study-review-20261022/benign-expanded-5min` | Ledger: *Observation-Length Benign Diversity Fixed: 8 Held-Out Benign Programs; 5-Min Combined Scoring, 2026-11-06* | 0 |
| `additional-study-review-20261022/benign-rest-5min` | Ledger: *5-Min Benign Validation Gap (top/lowrate Never Ran) + Timing Control + Bursty/Short Benign Collection, 2026-11-07* | 0 |
| [`additional-study-review-20261022/botiot-sweep`](additional-study-review-20261022/botiot-sweep/) | docs: [BOTIOT_RESULT.md](additional-study-review-20261022/botiot-sweep/BOTIOT_RESULT.md) | 1 |
| `additional-study-review-20261022/c2-viability` | Ledger: *Host-Evasive C2 Viability Probe Built And Frozen (No VM Yet), 2026-10-25* | 0 |
| [`additional-study-review-20261022/capture-liveness-readiness`](additional-study-review-20261022/capture-liveness-readiness/) | Ledger: *Actual V2 Capture-Liveness Attempt Stopped And Prefix Audited, 2026-10-23* | 6 |
| [`additional-study-review-20261022/capture-liveness-v3-readiness`](additional-study-review-20261022/capture-liveness-v3-readiness/) | Ledger: *Actual V3 Launch Stopped Before Controls And Audited, 2026-10-23* | 6 |
| [`additional-study-review-20261022/capture-liveness-v4-readiness`](additional-study-review-20261022/capture-liveness-v4-readiness/) | Ledger: *Actual V4 Six-Control Diagnostic Passed And Independently Audited, 2026-10-23* | 6 |
| `additional-study-review-20261022/cic-ddos-sweep` | Ledger: *Network-Strong: Triage Recovered + CIC 7-Type Sweep Strong; Live Flood Elicitation Needs Per-Family C2 RE (0/29), 2026-10-26* | 0 |
| [`additional-study-review-20261022/cicynu-external`](additional-study-review-20261022/cicynu-external/) | Ledger: *CIC-YNU-IoTMal Scored (Retrained Inside It); Further Paired Datasets Checked, 2026-11-23*; docs: [README.md](additional-study-review-20261022/cicynu-external/README.md) | 4 |
| [`additional-study-review-20261022/collector-v18-frozen`](additional-study-review-20261022/collector-v18-frozen/) | Ledger: *Benchmark No-Traffic Root Cause Verified; V4 Probe Draft Repaired Locally, 2026-10-24* | 1 |
| [`additional-study-review-20261022/collector-v19`](additional-study-review-20261022/collector-v19/) | Ledger: *Benchmark No-Traffic Root Cause Verified; V4 Probe Draft Repaired Locally, 2026-10-24* | 1 |
| [`additional-study-review-20261022/collector-v19-frozen`](additional-study-review-20261022/collector-v19-frozen/) | Ledger: *Runner .20 Installed; .20 Integrity Battery On The Headless Quiet Snapshot Launched, 2026-10-24* | 1 |
| [`additional-study-review-20261022/collector-v20`](additional-study-review-20261022/collector-v20/) | Ledger: *Runner .20 Candidate Built And Verified Locally (Not Installed), 2026-10-24* | 1 |
| [`additional-study-review-20261022/collector-v21`](additional-study-review-20261022/collector-v21/) | Ledger: *Observation-Length Pilot COLLECTED: 20s Truncates 70-93% Of Malware Behavior; Scaled 50+50 Launched, 2026-11-05* | 1 |
| [`additional-study-review-20261022/collector-v21-frozen`](additional-study-review-20261022/collector-v21-frozen/) | Ledger: *Observation-Length Pilot COLLECTED: 20s Truncates 70-93% Of Malware Behavior; Scaled 50+50 Launched, 2026-11-05* | 1 |
| [`additional-study-review-20261022/collector-v22`](additional-study-review-20261022/collector-v22/) | Ledger: *Observation-Length 5-Minute Pilot Built And Frozen (No VM Yet), 2026-11-05* | 2 |
| [`additional-study-review-20261022/combined-analysis`](additional-study-review-20261022/combined-analysis/) | Ledger: *Joint X64 And I386 Compatibility And Training, 2026-10-22* | 4 |
| [`additional-study-review-20261022/combined-surface-expanded`](additional-study-review-20261022/combined-surface-expanded/) | Ledger: *Paper Switched To Expanded Combined-Surface Pool, 2026-10-27* | 1 |
| [`additional-study-review-20261022/combined-surface-repeated-cv`](additional-study-review-20261022/combined-surface-repeated-cv/) | Ledger: *Combined-Surface Repeated Grouped CV (10 Fold Seeds), 2026-10-27* | 1 |
| [`additional-study-review-20261022/committee-eval-20261113`](additional-study-review-20261022/committee-eval-20261113/) | Ledger: *Committee Response: Rigor, Attribution, Switch Gap, Datasheet (Offline), 2026-11-13* and its follow-ups to 2026-11-17; docs: [REPORT.md](additional-study-review-20261022/committee-eval-20261113/REPORT.md), [baselines/README.md](additional-study-review-20261022/committee-eval-20261113/baselines/README.md), [datasheet/DATASHEET.md](additional-study-review-20261022/committee-eval-20261113/datasheet/DATASHEET.md) | 80 |
| `additional-study-review-20261022/current-release-assessments` | Ledger: *Additional Benign Guest Gate And Sixteen-Unit Assessment, 2026-10-23* | 0 |
| [`additional-study-review-20261022/deployment-design-20261107`](additional-study-review-20261022/deployment-design-20261107/) | Ledger: *5-Min Benign Validation Gap (top/lowrate Never Ran) + Timing Control + Bursty/Short Benign Collection, 2026-11-07* | 2 |
| `additional-study-review-20261022/evasive-viability` | Ledger: *Host-Evasive Class Deepened (Rekoobe/BPFDoor) + Second Viability Probe, 2026-10-25* | 0 |
| [`additional-study-review-20261022/exec-identity-readiness`](additional-study-review-20261022/exec-identity-readiness/) | Ledger: *Exec-Inode Attestation Gate Prepared, 2026-10-23* | 3 |
| [`additional-study-review-20261022/extension-audit-20261112`](additional-study-review-20261022/extension-audit-20261112/) | Ledger: *Full Audit Of The 68 Extra .21 Runs, 2026-11-12* | 1 |
| `additional-study-review-20261022/flood21-collect` | Ledger: *Observation-Length Check For The Advisor's Multi-Minute Request, 2026-11-05* | 0 |
| `additional-study-review-20261022/gafgyt-observe` | Ledger: *Bot-Flooding Route Phase 1 + Phase 2: Gafgyt/Kaiten C2 Handshake Captured (no attack), 2026-10-25* | 0 |
| [`additional-study-review-20261022/gafgyt-phase2`](additional-study-review-20261022/gafgyt-phase2/) | Ledger: *Bot-Flooding Route Phase 1 + Phase 2: Gafgyt/Kaiten C2 Handshake Captured (no attack), 2026-10-25* | 2 |
| [`additional-study-review-20261022/gafgyt-phase3`](additional-study-review-20261022/gafgyt-phase3/) | Ledger: *Bot-Flooding Phase 3: Commanded Flood Blocked At ircd-Emulation; Autonomous SYN-Flood Captured, 2026-10-25* | 8 |
| [`additional-study-review-20261022/historical-run-audit`](additional-study-review-20261022/historical-run-audit/) | Ledger: *Historical Run Audit Of All 7,337 Runs, 2026-10-24* | 1 |
| [`additional-study-review-20261022/host-gap-check-20261107`](additional-study-review-20261022/host-gap-check-20261107/) | Ledger: *5-Min Benign Validation Gap (top/lowrate Never Ran) + Timing Control + Bursty/Short Benign Collection, 2026-11-07* | 16 |
| `additional-study-review-20261022/i386-network-builds` | Ledger: *Real-Collection Plan On .21 Drafted; User Decisions Recorded, 2026-10-24* | 0 |
| [`additional-study-review-20261022/improvement-results-20261027`](additional-study-review-20261022/improvement-results-20261027/) | docs: [RESULTS.md](additional-study-review-20261022/improvement-results-20261027/RESULTS.md), [task3_cohort_expansion.md](additional-study-review-20261022/improvement-results-20261027/task3_cohort_expansion.md), [task4_botnet_shaped_benign.md](additional-study-review-20261022/improvement-results-20261027/task4_botnet_shaped_benign.md) | 4 |
| [`additional-study-review-20261022/integrated-collector-readiness`](additional-study-review-20261022/integrated-collector-readiness/) | Ledger: *Separately Versioned Integrated Collector Prepared, 2026-10-23* | 4 |
| `additional-study-review-20261022/integrity-v19` | Ledger: *Collector Integrity Test Battery Prepared, 2026-10-24* | 0 |
| `additional-study-review-20261022/integrity-v20` | Ledger: *Runner .20 Installed; .20 Integrity Battery On The Headless Quiet Snapshot Launched, 2026-10-24* | 0 |
| `additional-study-review-20261022/integrity-v21` | Ledger: *Runner .21 (Microsecond Window Anchor) Installed; .21 Integrity Battery Launched, 2026-10-24* | 0 |
| [`additional-study-review-20261022/iot23-external`](additional-study-review-20261022/iot23-external/) | Ledger: *IoT-23 External Check Of The Network Half (Offline), 2026-11-05* | 6 |
| [`additional-study-review-20261022/launcher-ablation`](additional-study-review-20261022/launcher-ablation/) | Ledger: *Cohort Captures Packaged For The Switch Replays + 1 s Offline Reference, 2026-11-08*; docs: [README.md](additional-study-review-20261022/launcher-ablation/README.md) | 4 |
| [`additional-study-review-20261022/launcher-ablation-05s`](additional-study-review-20261022/launcher-ablation-05s/) | Ledger: *Launcher Ablation Rerun At 0.5 s With Durable Scripts, 2026-11-11*; docs: [README.md](additional-study-review-20261022/launcher-ablation-05s/README.md) | 2 |
| [`additional-study-review-20261022/lidds-cross`](additional-study-review-20261022/lidds-cross/) | Ledger: *Cross-Dataset Test: LID-DS 2021 <-> Our Dataset Does Not Transfer, 2026-11-12*; docs: [README.md](additional-study-review-20261022/lidds-cross/README.md) | 5 |
| [`additional-study-review-20261022/lidds-external`](additional-study-review-20261022/lidds-external/) | Ledger: *LID-DS Test 1 Over Ten Fold Assignments + Thesis Write-Up, 2026-11-06* | 14 |
| [`additional-study-review-20261022/lowrate21-collect`](additional-study-review-20261022/lowrate21-collect/) | Ledger: *Low-Rate Benign Collection Done: IoT-23 Device False Alarms 57% -> 38%, Table V Slightly Up, 2026-11-06* | 1 |
| `additional-study-review-20261022/matched45-builds` | Ledger: *Approved Matched 45+45 Identity Preparation, 2026-10-22* | 0 |
| `additional-study-review-20261022/matched45-identities` | Ledger: *Approved Matched 45+45 Identity Preparation, 2026-10-22* | 0 |
| `additional-study-review-20261022/matched45-preparation` | Ledger: *Approved Matched 45+45 Identity Preparation, 2026-10-22* | 0 |
| `additional-study-review-20261022/matched45-readiness` | Ledger: *Matched45 Collection Readiness Accepted, 2026-10-22* | 0 |
| `additional-study-review-20261022/matched45-workloads` | Ledger: *Matched45 Benign Readiness Authorized, 2026-10-22* | 0 |
| `additional-study-review-20261022/merge-readiness` | Ledger: *Original Source Recovery And Merge-Readiness Gate, 2026-10-22* | 0 |
| [`additional-study-review-20261022/net-strong-viability`](additional-study-review-20261022/net-strong-viability/) | Ledger: *Option B: Offline C2 RE Triage + Targeted Controlled-C2 Flood Run -> 0/3 (live-bot route exhausted), 2026-10-26* | 12 |
| `additional-study-review-20261022/netcat-musl-dependencies` | Ledger: *Compatible Netcat Repair And Allocator Candidate, 2026-10-22* | 0 |
| [`additional-study-review-20261022/network-census-20261116`](additional-study-review-20261022/network-census-20261116/) | Census of the Linux families with network-active x86 samples on Triage and MalwareBazaar, and their download into quarantine (nothing executed): the source of the session lab's Triage cohort, 2026-11-16 | 5 |
| [`additional-study-review-20261022/paper-check-20261028`](additional-study-review-20261022/paper-check-20261028/) | Ledger: *Paper Check Of The Overleaf Version Against The Data, 2026-10-28* | 4 |
| [`additional-study-review-20261022/pc1-part3-check-20261111`](additional-study-review-20261022/pc1-part3-check-20261111/) | Ledger: *PC1 Part 3 Checked: Libc Start-Up Residual Confirmed Call By Call; Table V Depends On scikit-learn 1.8, 2026-11-11*; docs: [README.md](additional-study-review-20261022/pc1-part3-check-20261111/README.md) | 5 |
| [`additional-study-review-20261022/pc1-static-benign`](additional-study-review-20261022/pc1-static-benign/) | Ledger: *PC1 Hand-Off Pushed; Encrypted-Traffic Collection Launched, 2026-11-15* (the dataset's static benign programs packed for PC1 part 6; the tarball stays local); docs: [static-benign/README.md](additional-study-review-20261022/pc1-static-benign/static-benign/README.md) | 2 |
| `additional-study-review-20261022/pilot-5min` | Ledger: *Observation-Length 5-Minute Pilot Built And Frozen (No VM Yet), 2026-11-05* | 0 |
| [`additional-study-review-20261022/precision-phase4`](additional-study-review-20261022/precision-phase4/) | Ledger: *Bot-Flooding Phase 4: Precision Harness Built; Kaiten-C2 Flood + Benign-Bulk Paired Capture (overnight), 2026-10-25* | 16 |
| `additional-study-review-20261022/quiet-ambient` | Ledger: *Benchmark No-Traffic Root Cause Verified; V4 Probe Draft Repaired Locally, 2026-10-24* | 0 |
| `additional-study-review-20261022/quiet-ambient-v2` | Ledger: *Quiet-v2.2 Configure Passed, Multiboot Stopped At Boot 1; Quiet-v2.3 Prepared, 2026-10-24* | 0 |
| `additional-study-review-20261022/quiet-ambient-v2-1` | Ledger: *Quiet-v2.1 Run Stopped At Configure; Quiet-v2.2 Prepared, 2026-10-24* | 0 |
| `additional-study-review-20261022/quiet-ambient-v2-2` | Ledger: *Quiet-v2.2 Configure Passed, Multiboot Stopped At Boot 1; Quiet-v2.3 Prepared, 2026-10-24* | 0 |
| `additional-study-review-20261022/quiet-ambient-v2-3` | Ledger: *Quiet-v2.3 Multiboot Found Real Boot-Time Background Traffic, 2026-10-24* | 0 |
| `additional-study-review-20261022/quiet-ambient-v3` | Ledger: *Quiet-v3.2: Nine Clean Headless Boots, Boot 10 Raced IPv4 DAD; Quiet-v3.3 Prepared, 2026-10-24* | 0 |
| `additional-study-review-20261022/quiet-ambient-v3-1` | Ledger: *Quiet-v3.1: Two Clean Headless Boots, Boot 3 Stalled; Quiet-v3.2 Prepared, 2026-10-24* | 0 |
| `additional-study-review-20261022/quiet-ambient-v3-2` | Ledger: *Quiet-v3.2: Nine Clean Headless Boots, Boot 10 Raced IPv4 DAD; Quiet-v3.3 Prepared, 2026-10-24* | 0 |
| `additional-study-review-20261022/quiet-ambient-v3-3` | Ledger: *Quiet-v3.3: Five Clean Boots, Boot 6 Hung Before Userspace; Hang Rate Measured, 2026-10-24* | 0 |
| `additional-study-review-20261022/quiet-ambient-v3-4` | Ledger: *Quiet Headless Environment Validated (Quiet-v3.4 Run + v3.5 ICMP Re-Audit), 2026-10-24* | 0 |
| [`additional-study-review-20261022/realtools`](additional-study-review-20261022/realtools/) | Ledger: *Combined-Surface Repeated Grouped CV (10 Fold Seeds), 2026-10-27* | 2 |
| `additional-study-review-20261022/realtools-collect` | Ledger: *Combined-Surface Repeated Grouped CV (10 Fold Seeds), 2026-10-27* | 0 |
| `additional-study-review-20261022/release-contracts` | Ledger: *Approved Scoped Contract, Source Review And Performance Gate Prepared, 2026-10-23* | 0 |
| `additional-study-review-20261022/release-proposals` | Ledger: *Approved Scoped Contract, Source Review And Performance Gate Prepared, 2026-10-23* | 0 |
| [`additional-study-review-20261022/release-specific-assessments`](additional-study-review-20261022/release-specific-assessments/) | Ledger: *Actual V3 Performance Stopped; Exact Release Inputs Audited, 2026-10-23* | 1 |
| [`additional-study-review-20261022/remediation-audit`](additional-study-review-20261022/remediation-audit/) | Ledger: *Offline Remediation And Binary Relationship Audit, 2026-10-22* | 1 |
| `additional-study-review-20261022/remediation-feasibility` | Ledger: *Offline Source Feasibility And Attribution Design, 2026-10-22* | 0 |
| `additional-study-review-20261022/remediation-guest-readiness` | Ledger: *Remediation Guest Results And Static Matching, 2026-10-22* | 0 |
| `additional-study-review-20261022/remediation-preparation` | Ledger: *Actual I386 Failure And Separate V6 Gate Prepared, 2026-10-23* | 0 |
| `additional-study-review-20261022/remediation-static-guest-readiness` | Ledger: *Compatible Netcat Repair And Allocator Candidate, 2026-10-22* | 0 |
| `additional-study-review-20261022/remediation-tools` | Workspace-local tools (pyelftools, TLSH) used by the remediation audit; not our code. | 0 |
| `additional-study-review-20261022/remediation-workload-readiness` | Ledger: *Remediation Collection Readiness Continued, 2026-10-22* | 0 |
| `additional-study-review-20261022/revision5-collection` | Ledger: *Matched-Cohort Payload + Driver Built And Frozen (revision5-matched), 2026-10-25* | 0 |
| `additional-study-review-20261022/revision5-model-fit` | Ledger: *Matched-Cohort Held-Out Fit: Confounds Controlled, Host Strong On A Draw, Hybrid != Host, 2026-10-25* | 0 |
| [`additional-study-review-20261022/sample-intel-20261113`](additional-study-review-20261022/sample-intel-20261113/) | Ledger: *Network Behaviour Of The 99 On Triage's Internet Sandbox, 2026-11-15* (and the platform lookups of 2026-11-13 and 2026-11-17); docs: [README.md](additional-study-review-20261022/sample-intel-20261113/README.md) | 4 |
| [`additional-study-review-20261022/sample-inventory-20261112`](additional-study-review-20261022/sample-inventory-20261112/) | Ledger: *On-Disk Inventory Of Native Samples Outside The 99, 2026-11-12* | 1 |
| `additional-study-review-20261022/scale-5min` | Ledger: *Observation-Length Pilot COLLECTED: 20s Truncates 70-93% Of Malware Behavior; Scaled 50+50 Launched, 2026-11-05* | 0 |
| [`additional-study-review-20261022/scoped-hybrid-eval`](additional-study-review-20261022/scoped-hybrid-eval/) | Ledger: *Scoped Hybrid Numeric Evaluation: Flood Result Holds On Real Captures; Host-Evasive Claim Retracted, 2026-10-26* | 2 |
| [`additional-study-review-20261022/scoped-performance`](additional-study-review-20261022/scoped-performance/) | Ledger: *Benchmark No-Traffic Root Cause Verified; V4 Probe Draft Repaired Locally, 2026-10-24* | 4 |
| [`additional-study-review-20261022/scoped-performance-v2`](additional-study-review-20261022/scoped-performance-v2/) | Ledger: *Actual Performance V2 Stopped And Saved Prefix Audited, 2026-10-23* | 3 |
| [`additional-study-review-20261022/scoped-performance-v3`](additional-study-review-20261022/scoped-performance-v3/) | Ledger: *Benchmark No-Traffic Root Cause Verified; V4 Probe Draft Repaired Locally, 2026-10-24* | 3 |
| [`additional-study-review-20261022/scoped-performance-v4`](additional-study-review-20261022/scoped-performance-v4/) | Ledger: *Benchmark No-Traffic Root Cause Verified; V4 Probe Draft Repaired Locally, 2026-10-24* | 2 |
| [`additional-study-review-20261022/sensor-visibility`](additional-study-review-20261022/sensor-visibility/) | Ledger: *Sensor-Visibility Test: 5 Tsunami Bots Quit When Our Collector Is Visible, 2026-11-15*; docs: [README.md](additional-study-review-20261022/sensor-visibility/README.md) | 7 |
| [`additional-study-review-20261022/session-lab`](additional-study-review-20261022/session-lab/) | Ledger: *Session Lab (LID-DS-Like Sessions, Network Captured On The Sink): Pilot Approved And Launched, 2026-11-15* to *Malware-Only Session-Lab Plan Built And Frozen (Not Run), 2026-11-19* (`internet/`: a benign-only copy of the lab on real Internet, 2026-11-19, not run); docs: [DESIGN.md](additional-study-review-20261022/session-lab/DESIGN.md), [REPORT.md](additional-study-review-20261022/session-lab/REPORT.md), [base/20261117c/README.md](additional-study-review-20261022/session-lab/base/20261117c/README.md) | 79 |
| [`additional-study-review-20261022/short-windows-20261120`](additional-study-review-20261022/short-windows-20261120/) | Ledger: *Dataset Rows Rebuilt With 0.25-s And 0.1-s Windows (Paper 240 And Session 435), Offline, 2026-11-20*; docs: [README.md](additional-study-review-20261022/short-windows-20261120/README.md) | 9 |
| [`additional-study-review-20261022/sink-sinkhole`](additional-study-review-20261022/sink-sinkhole/) | Ledger: *Passive Sinkhole For The Sink Built And Tested Locally (Not Applied), 2026-11-12* | 10 |
| [`additional-study-review-20261022/sinkhole-c2-5min`](additional-study-review-20261022/sinkhole-c2-5min/) | Ledger: *Sinkhole C2 Experiment Approved; Guest Check First, 2026-11-13* (builder and driver: `build_sinkhole_c2_payload.py`, `collect_sinkhole_c2.py` one level up) | 4 |
| [`additional-study-review-20261022/sliver-c2-5min`](additional-study-review-20261022/sliver-c2-5min/) | Ledger: *Sliver C2 testbed prepared, 2026-11-13* (our own Sliver server + implants in the sealed lab; `PLAN.md`, `rc/`; binaries git-ignored) | 13 |
| [`additional-study-review-20261022/sockowner-check`](additional-study-review-20261022/sockowner-check/) | Ledger: *Committee Response: Rigor, Attribution, Switch Gap, Datasheet (Offline), 2026-11-13* (socket-level attribution: the live benign check and the run beside malware) | 8 |
| `additional-study-review-20261022/source-recovery` | Ledger: *Original Source Recovery And Merge-Readiness Gate, 2026-10-22* | 0 |
| [`additional-study-review-20261022/switch-exact-1s`](additional-study-review-20261022/switch-exact-1s/) | Ledger: *Cohort Captures Packaged For The Switch Replays + 1 s Offline Reference, 2026-11-08*; docs: [README.md](additional-study-review-20261022/switch-exact-1s/README.md) | 3 |
| [`additional-study-review-20261022/thesis-experiments-20261103`](additional-study-review-20261022/thesis-experiments-20261103/) | docs: [PLAN.md](additional-study-review-20261022/thesis-experiments-20261103/PLAN.md), [THESIS_FINDINGS.md](additional-study-review-20261022/thesis-experiments-20261103/THESIS_FINDINGS.md) | 13 |
| [`additional-study-review-20261022/thesis-review-20261122`](additional-study-review-20261022/thesis-review-20261122/) | Ledger: *Thesis Rewritten For The Final Architecture And The Review's Changes (Not Committed), 2026-11-22* | 4 |
| [`additional-study-review-20261022/thesis-review-20261123`](additional-study-review-20261022/thesis-review-20261123/) | Ledger: *Thesis And Journal Fixes From The Readiness Review; ADFA-LD Probe Re-Run; Paired IoT Datasets Inspected, 2026-11-23* | 1 |
| `additional-study-review-20261022/toolchain21-collect` | Ledger: *Committee Response: Rigor, Attribution, Switch Gap, Datasheet (Offline), 2026-11-13* (the toolchain-matched benign collection; driver `collect_toolchain21.py` one level up) | 0 |
| `additional-study-review-20261022/tools21-build` | Ledger: *PC1 Hand-Off Pushed; Encrypted-Traffic Collection Launched, 2026-11-15* (attack-tool build preparation, stopped; authenticated sources only, git-ignored) | 0 |
| `additional-study-review-20261022/topup-5min` | Ledger: *Observation-Length Study: Final Real-Data Scoring + Sink Outage Found And Measured, 2026-11-07* | 0 |
| `additional-study-review-20261022/topup-5min-finish` | Ledger: *Observation-Length Study: Final Real-Data Scoring + Sink Outage Found And Measured, 2026-11-07* | 0 |
| [`additional-study-review-20261022/transport21`](additional-study-review-20261022/transport21/) | Ledger: *PC1 Hand-Off Pushed; Encrypted-Traffic Collection Launched, 2026-11-15* (our own client and server over HTTP, TLS 1.1 to 1.3 and QUIC; the built binary stays local) | 6 |
| `additional-study-review-20261022/transport21-collect` | Ledger: *PC1 Hand-Off Pushed; Encrypted-Traffic Collection Launched, 2026-11-15* (the encrypted-traffic collection; driver `collect_transport21.py` one level up) | 0 |
| `additional-study-review-20261022/v19-pilot` | Ledger: *Benchmark No-Traffic Root Cause Verified; V4 Probe Draft Repaired Locally, 2026-10-24* | 0 |
| [`additional-study-review-20261022/v19-small-collection`](additional-study-review-20261022/v19-small-collection/) | Ledger: *New Installed-.19 Driver And Small Plan Prepared Locally, 2026-10-24* | 1 |
| `additional-study-review-20261022/v21-collection` | Ledger: *v21 Guarded Exploratory Fit: Held-Out Weak, Nuisance Shortcut Dominates, 2026-10-25* | 0 |
| `additional-study-review-20261022/v21-collection-selection` | Ledger: *150+150 Selection Resolved To Diverse ~97+97, 2026-10-24* | 0 |
| `additional-study-review-20261022/v21-model-fit` | Ledger: *v21 Guarded Exploratory Fit: Held-Out Weak, Nuisance Shortcut Dominates, 2026-10-25* | 0 |
| [`additional-study-review-20261022/vm-batches-20261031`](additional-study-review-20261022/vm-batches-20261031/) | docs: [PROTOCOL.md](additional-study-review-20261022/vm-batches-20261031/PROTOCOL.md) | 28 |
| `additional-study-review-20261022/wgetp-5min` | Ledger: *Observation-Length Benign Diversity Fixed: 8 Held-Out Benign Programs; 5-Min Combined Scoring, 2026-11-06* | 0 |
| `additional-study-review-20261022/window-length-test` | Ledger: *Window-Length Test For 10-s Switch Reads (Offline), 2026-11-06* | 0 |
| [`additional-study-review-20261022/within-family-exploratory`](additional-study-review-20261022/within-family-exploratory/) | Ledger: *Exploratory Within-Family Resplit And Refit, 2026-10-22* | 3 |
