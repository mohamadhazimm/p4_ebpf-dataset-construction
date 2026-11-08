# Handoff: collector schema .19 + quiet snapshot, ready for a small collection

Date: 2026-10-24. Audience: a coding agent that will run the next small collection with the user.

## Context

Lab at `/home/ali/Desktop/Hazim`. Study repo: `vbox-runs/hybrid-rf-study-20261010/`. Work dir:
`data/versioned-collector/additional-study-review-20261022/` (call it `$W`). Read
`/home/ali/Desktop/Hazim/AGENTS.md` first. It is the evidence ledger and the newest entries
(2026-10-24) are at the top. Study goal: compare three RF IDS models, host-only (eBPF, 145 cols),
network-only (P4-shaped PCAP features, 145 cols) and hybrid (290 cols). Samples execute ONLY inside the
isolated VirtualBox guest `Ubuntu-Clean-24.04` (NIC1 `intnet=malnet`, NICs 2-8 `none`), with the `Sink` VM
as the fake internet. Nothing is ever executed on the host. Every VM step needs the user's explicit approval.

## The problem that was fixed

The `.18` runner rejected any capture with zero packets and zero NIC deltas
(`packet_capture_interface_no_traffic`, `src/malware_runner.py` `assess_collection_quality`). That gate counts
ALL frames, so it measured ambient traffic, not whether capture worked. Verified with tshark on saved PCAPs:
the only enp0s3 traffic in a quiet guest is NetworkManager connectivity checks (HTTP to the Sink) plus chrony
NTP DNS, avahi mDNS, cups-browsed mDNS and reverse DNS. Check intervals double (16/32/64s...), so about 3
minutes after boot a silent task captures nothing. Three performance attempts died at case 7 for exactly this.
The same ambient traffic is in all 417 existing captures, identical for benign and malware (it dilutes the
network and hybrid models). Separately, the performance benchmark (V4) stopped at case 8 on a 1.25 ratio limit
(fixed ~50 ms sidecar setup vs ~15 ms tasks). That is NOT needed for collection. Do not run `run_performance_v*`.

## The fix (two parts)

1. **Quiet snapshot** `clean-quiet-ambient-20261024T080813430717Z`, a child of
   `clean-current-runner-2026-10-18.1-malware` (parent untouched). Built by `$W/quiet_ambient.py` using
   `$W/quiet_guest.sh`: NetworkManager `[connectivity] enabled=false`
   (`/etc/NetworkManager/conf.d/99-hazim-quiet-ambient.conf`), chrony disabled, avahi socket+service masked,
   cups-browsed masked, geoclue masked. A/B over the same 240 s boot window: 180 frames before, 16 after
   (the positive-control HTTP stream plus 4 ARP), zero frames from the disabled sources. Evidence:
   `$W/quiet-ambient/20261024T080813430717Z/`.
2. **Runner `.19`** (`src/malware_runner.py`, schema `2026-10-24.19`, SHA
   `37e5a156774663214ba231825c5174c048d5468747b0a213624153426af60b0a`, 169 features unchanged). It is `.18`
   plus per-sample capture-path probes: one bounded TCP connect to `10.0.0.1:80` (1 s timeout, closed with RST,
   0.2 s settle) right after tcpdump readiness and one after eBPF shutdown, both REQUIRED to be recovered from
   the published PCAP outside the feature windows. Otherwise the case is rejected with `capture_path_probe_*`.
   Probes never relax an earlier rejection and are outside task wall, telemetry windows, P4 features and the
   target cgroup. Because probe frames are captured, the old no-traffic reason can no longer fire. A silent
   benign task is accepted when both probes are recovered. Probe code: `$W/performance_v4.py` (guest-tested in
   the V4 attempt); installed by `$W/install_runner_v19.py` (AST-identical to the piloted draft
   `collector-v19/malware_runner.py`, SHA `bef85019...`; the file hash differs only by formatting/comments).
   A verbatim `.18` copy is at `$W/collector-v18-frozen/malware_runner.py` (`3bc8f91b...`). `.18` is NOT in
   git, so never overwrite that copy.

## Verified results

- Benign-only pilot `$W/v19-pilot/20261024T083321478831Z/` (18 cases through the real batch script on the quiet
  baseline, `validation-20261024T084742214380Z.json`): 17/17 valid cases accepted. The 18th, `net_r3`, was my
  design error (the control program only accepts repeat 1-2), not a collector fault. Accepted cases have zero
  loss/ABI, both probes independently recovered with Scapy, zero frames from the disabled services, P4 unique
  alignment with exact parity (145 comparisons each), and the network controls show their marked HTTP GET and
  exactly 6 UDP datagrams in-window. Null post-target syscall maxima: amd64-dynamic 30, amd64-static 20,
  i386-static 20. All 145 P4 features are exactly zero for silent benign tasks (old captures had ~60+ ambient
  frames). Residual: 0-3 in-window ARP frames (probe-induced and boot announcements) touch only the 9
  `net_*` counters. Static ARP entries on guest and Sink would remove them.
- Runner and exec-boundary tests: 60/60 on installed `.19`
  (`tests/test_malware_runner_hostmon.py` gained `test_capture_path_probes_must_bracket_the_feature_windows`).
- `collection_ready=false`: no malware has run on `.19` yet. Probe behaviour under real malware load is untested.

## KNOWN BLOCKERS before any launch

1. **Frozen drivers now fail closed.** `cohort-100x100-v18-20261021/redesign-native-x64/run_readiness.py`
   `verify_production()` pins `src/malware_runner.py` to the `.18` hash. After the install it raises
   `production provenance changed: src/malware_runner.py`. This breaks `pilot_v19.py` (also hard-codes the draft
   hash), `ready_matched45.py`, `collect_matched45.py` and every driver that imports the helper. Do NOT edit
   `run_readiness.py` (dozens of frozen tools and measured evidence depend on it). Write a NEW driver that
   verifies three hashes: `src/malware_runner.py` = `37e5a156...`,
   `scripts/vbox_malware_batch.sh` = `4490a4cec6e26307d1f3e00f28c09a07d6b8fdcfd8bc12a12961ee34f6887f9f`,
   `scripts/stage_versioned_runner_snapshot.sh` = `5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103`.
   Reuse its VM helpers (`vbox`, `vm_info`, `isolated`, `credentials`) by import, and update
   `pilot_v19.validate()`'s runner-hash check to the installed hash.
2. **Fresh snapshot required.** The pilot snapshot holds the draft runner, so the batch's guest-vs-host hash check
   refuses it. Stage a new child from the quiet baseline with the real scripts:
   `scripts/stage_versioned_runner_snapshot.sh --vm Ubuntu-Clean-24.04 --guest-user csci
   --baseline-snapshot clean-quiet-ambient-20261024T080813430717Z --new-snapshot <new name>
   --schema-version 2026-10-24.19 --guest-setup <setup>`. No shadow root is needed any more.
3. **New dataset, not an extension.** Quiet-environment `.19` captures must NOT be merged with the 417 `.18`
   captures without a compatibility analysis. Group roles/global exclusions from the ledger still apply, and the
   previously scored validation sets are consumed, so results here are exploratory.

## What to do

1. Ask the user to define the cohort. Keep it small (a few dozen cases). Frozen identities, argument files and
   fixtures to reuse: the matched45 manifest `$W/matched45-readiness/20261022T072823231146Z/manifest.json`
   (45 benign programs, 45 cap-10 family-balanced malware identities, 6 nulls) and the family labels in
   `data/malware/revision4/training521_holdout461_20261017/malware_hash_labels.csv`. Include the per-mode
   nulls (amd64-dynamic, amd64-static, i386-static). Follow `ready_matched45.py` for building the payload
   (`samples/<name>.zip`, `arguments/<name>.json`, fixtures) and the staging setup script. A raw ELF must be
   wrapped as a one-member ZIP. Outer ZIP names must match the batch's name regex, so no `+`.
2. Freeze before launching: the case list, a seed-fixed interleaved order of benign/malware/null, the payload and
   setup hashes, and the validation criteria. Write a protocol file. Get explicit user approval of the frozen plan.
3. Preflight (read-only): original snapshot `clean-tls-paired-2026-10-19` powered off, Sink running, both on
   `intnet=malnet` with NICs 2-8 `none`, no other collector (`export_original_sources.check_competitors`), take
   `readiness.lock`.
4. Stage, then batch dry-run, then collect. Settings: `--timeout 20 --window-sec 0.5 --iface enp0s3 --ebpf
   --fixed-observation --common-launch-wrapper`, `--schema-version 2026-10-24.19`, one batch with no
   `--resume`. No retries or replacements. Preserve failures. Always restore the original snapshot, power off,
   and verify isolation (`final_vm_state.json`).
5. Validate offline per case (adapt `pilot_v19.validate`; malware does NOT need exit 0): retrieval completed;
   `.19` schema/hash; quality accepted; exact target exec observed; mode/linkage; 40x169 finite; archive hashes;
   PCAP records == tcpdump counters; zero loss/ABI; both probes recovered
   (`audit_performance_v4.audit_probe`); zero disabled-source frames (`quiet_ambient.summarize`); P4 unique alignment
   with parity. Report the exclusions (no exec, rejected quality, unretrieved) rather than hiding them.
6. Model check: with only a few dozen cases, accuracy is a health check, not a result. Train/score with the frozen
   145/145/290 protocol (training-only feature selection, RF500 balanced, seed 42, threshold 0.5), reusing
   `$W/analyze_matched45.py` / `train_model.py` patterns, on the `.19` captures only.
7. Append every attempt (command, hashes, outcome, cleanup) to `AGENTS.md`.

## Pitfalls hit this session

- `sed -i` through a symlinked scratch tree rewrote a real test file. Use the Edit tool and never edit through symlinks.
- `git diff` is meaningless for `.18` and the tests (untracked). Verify with `cmp` and hashes.
- Never `cat`/`grep` a generated `setup_guest.sh` (embedded base64 payload, up to 64 MB).
- Guest-side results appear only when the guest run ends. Do not poll for per-case progress.
- Do not edit the pinned batch/stage scripts while a batch runs. Do not touch measured/frozen artifacts.
- Record unfinished drafts in the ledger. An unrecorded V4 draft cost a session before.
