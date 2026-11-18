#!/bin/bash
# Start the rest of the main plan after the Triage cohort, only if the cohort's Sink restore passed (Sink back to its
# original state) and the guest is powered off on the original snapshot.
#   chain_rest.sh <triage pid> <triage attempt> <rest attempt> <rest protocol sha256> <deadline UTC> <approval>
set -u
prev_pid="$1"; prev="$2"; rest="$3"; sha="$4"; deadline="$5"; approval="$6"
cd "$(dirname "$0")" || exit 2
log="$rest/chain.log"
echo "$(date -u +%FT%TZ) waiting for the Triage cohort pid $prev_pid" >> "$log"
while kill -0 "$prev_pid" 2>/dev/null; do sleep 15; done
sessions=$(ls -1 "$prev"/phases/sessions/result-*.json 2>/dev/null | tail -1)
echo "$(date -u +%FT%TZ) Triage sessions phase: $(grep -o '"status": "[a-z]*"' "$sessions" 2>/dev/null | tail -1) ($sessions)" >> "$log"
restore=$(ls -1 "$prev"/phases/sink-restore/result-*.json 2>/dev/null | tail -1)
if [ -z "$restore" ] || ! grep -q '"status": "passed"' "$restore"; then
  echo "$(date -u +%FT%TZ) Triage Sink restore not passed ($restore): rest not started" >> "$log"
  exit 1
fi
sleep 60
state=$(VBoxManage showvminfo Ubuntu-Clean-24.04 --machinereadable 2>/dev/null | grep -E '^(VMState|CurrentSnapshotName)=' | tr '\n' ' ')
echo "$(date -u +%FT%TZ) guest: $state" >> "$log"
case "$state" in
  *'VMState="poweroff"'*'CurrentSnapshotName="clean-tls-paired-2026-10-19"'*) ;;
  *) echo "$(date -u +%FT%TZ) guest not powered off on the original snapshot: rest not started" >> "$log"; exit 1 ;;
esac
echo "$(date -u +%FT%TZ) starting the rest (deadline $deadline)" >> "$log"
exec /usr/bin/python3 -u run_session_rest.py --run-all --attempt "$rest" --protocol-sha256 "$sha" \
  --approval "$approval" --deadline-utc "$deadline" >> "$rest/rest.log" 2>&1 < /dev/null
