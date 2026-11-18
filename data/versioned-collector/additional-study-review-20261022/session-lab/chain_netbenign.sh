#!/bin/bash
# Run the frozen network-active benign batch, then its analysis and the pre-registered scoring. Needs the user's
# approval words as $1. Starts only when no other session-lab collection runs and the guest is powered off on the
# original snapshot.
#   ./chain_netbenign.sh "<user's approval words>"
set -u
cd "$(dirname "$0")" || exit 2
A=runs/20261117T113428913222Z
SHA=f4abe483aae251f422e4bf66559c23ae1b4da19d2c998f8f3ea25c5b5774feca
[ -n "${1:-}" ] || { echo "approval words required"; exit 2; }
log=$A/chain.log
echo "$(date -u +%FT%TZ) waiting for other collections" >> $log
while pgrep -f 'run_session_(rest|main|triage|flood|netpilot|lab|silentbenign).py --run-all' >/dev/null; do sleep 60; done
st=$(VBoxManage showvminfo Ubuntu-Clean-24.04 --machinereadable | grep -E '^(VMState|CurrentSnapshotName)=' | tr '\n' ' ')
echo "$(date -u +%FT%TZ) guest: $st" >> $log
case "$st" in *'VMState="poweroff"'*'CurrentSnapshotName="clean-tls-paired-2026-10-19"'*) ;; *) echo "guest not clean; stop" >> $log; exit 3;; esac
[ "$(sha256sum $A/protocol.json | cut -d' ' -f1)" = "$SHA" ] || { echo "protocol changed; stop" >> $log; exit 3; }
/usr/bin/python3 -u run_session_netbenign.py --run-all --attempt $A --protocol-sha256 $SHA --approval "$1" >> $A/run.log 2>&1
rc=$?          # read before the echo: "$(date ...) $?" would report date's status
echo "$(date -u +%FT%TZ) run exit $rc" >> $log
R="nice -n 19 /usr/bin/python3"
mkdir -p $A/analysis
$R analyze_session_lab.py $A --features --keep-going > $A/analysis/analyze.log 2>&1
arc=$?
echo "$(date -u +%FT%TZ) analysis exit $arc" >> $log
if [ -x final_netbenign.sh ]; then
  ./final_netbenign.sh $A >> $log 2>&1
  frc=$?
  echo "$(date -u +%FT%TZ) final_netbenign.sh exit $frc" >> $log
else
  echo "$(date -u +%FT%TZ) final_netbenign.sh missing; scoring not run" >> $log
fi
