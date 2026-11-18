#!/bin/bash
# Run the frozen silent-server benign batch and its pre-registered scoring. Needs the user's approval words as $1.
# Starts only when no other session-lab collection runs and the guest is powered off on the original snapshot.
#   ./chain_silentbenign.sh "<user's approval words>"
set -u
cd "$(dirname "$0")" || exit 2
A=runs/20261117T013400746805Z
SHA=ff7189c82cb3e163e9b12f7190b74a04dc9ae46f1e363610abcfd58028bd7248
[ -n "${1:-}" ] || { echo "approval words required"; exit 2; }
log=$A/chain.log
echo "$(date -u +%FT%TZ) waiting for other collections" >> $log
while pgrep -f 'run_session_(rest|main|triage|flood|netpilot|lab).py --run-all' >/dev/null; do sleep 60; done
st=$(VBoxManage showvminfo Ubuntu-Clean-24.04 --machinereadable | grep -E '^(VMState|CurrentSnapshotName)=' | tr '\n' ' ')
echo "$(date -u +%FT%TZ) guest: $st" >> $log
case "$st" in *'VMState="poweroff"'*'CurrentSnapshotName="clean-tls-paired-2026-10-19"'*) ;; *) echo "guest not clean; stop" >> $log; exit 3;; esac
[ "$(sha256sum $A/protocol.json | cut -d' ' -f1)" = "$SHA" ] || { echo "protocol changed; stop" >> $log; exit 3; }
/usr/bin/python3 -u run_session_silentbenign.py --run-all --attempt $A --protocol-sha256 $SHA --approval "$1" >> $A/run.log 2>&1
rc=$?          # read before the echo: "$(date ...) $?" would report date's status
echo "$(date -u +%FT%TZ) run exit $rc" >> $log
R="nice -n 19 /usr/bin/python3"
mkdir -p $A/analysis
$R analyze_session_lab.py $A --features --keep-going > $A/analysis/analyze.log 2>&1
arc=$?
$R score_silentbenign.py --attempt $A --out $A/analysis > $A/analysis/score.log 2>&1
src=$?
echo "$(date -u +%FT%TZ) analysis exit $arc, scoring exit $src" >> $log
