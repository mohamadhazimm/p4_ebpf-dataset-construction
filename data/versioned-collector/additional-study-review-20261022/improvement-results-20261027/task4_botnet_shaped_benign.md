# Task 4 — Botnet-shaped benign workloads: sourcing/build design (offline)

## Problem
Benign = coreutils-heavy CLI tools + a few downloads; malware = long-running,
forking, network-beaconing daemons (botnets/miners/ransomware). The host model's
separation may partly track "short CLI tool vs long daemon" (a workload-class
shortcut), not benign-vs-malicious. The ADFA rare-syscall-ratio / process-
structure features are exactly where this confound would live.

## Fix
Add benign workloads that are structurally botnet-shaped — long-running, fork/
spawn, network-beaconing, CPU-spinning — but legitimate and authenticated,
matched to the malware per-mode distribution and project-held-out. All are
buildable through the existing signed-apt + musl-static pipeline used for the
revision5 benign set, so they slot in without new infrastructure.

## Candidate workloads (map to malware behavior classes)
- Beaconing/C2-shaped (vs Sink, internal only):
  - headless IRC client (ii / irssi-dumb) connecting + idling on the Sink
  - MQTT pub/sub loop (mosquitto clients), periodic keepalive
  - P2P/DHT-shaped: transmission-cli / aria2 seeding to the Sink
  - periodic curl/wget keepalive loop (already partially present — formalize)
- Miner-shaped CPU load (fork/thread + sustained CPU, no mining):
  - stress-ng cpu/matrix stressors, openssl speed, sysbench cpu, xz -9 loops
- Forking server (spawn structure like a bot spreading):
  - busybox httpd / python http.server / dropbear serving the Sink
- Long-running with children:
  - make -j build job, rsync in daemon/transfer mode

## Design constraints (match the malware, kill the shortcut)
- Mode-matched: produce amd64-static, amd64-dynamic, i386-static variants to
  mirror the malware mode mix (esp. amd64-dynamic, currently benign-light).
- Activity-binned to overlap malware syscall-volume bands (reuse the
  revision5 host-preflight strace sizing so benign activity sits in the same
  bands — no new quiet=benign threshold).
- Project-held-out: whole upstream projects reserved for validation.
- Network-active ~a third, to the internal Sink only.

## Expected effect
If the host sensor still separates these daemon/beacon/CPU-heavy benign from
malware, the 0.93/robust-0.70 result is far more defensible; if it drops, we've
found the confound honestly and can report the corrected number. Either outcome
strengthens the paper.

## Gate
Benign-only (lower risk), but still VM collection → preflight→stage→dry-run→
collect, each needing explicit approval. Nothing here builds or runs yet.
