#!/bin/bash
# After the main collection: its final analysis, then the network-active pilot (user approval "yes please").
# Starts the pilot only if the main run's sessions phase and Sink restore passed and the analysis finished.
#   chain_netpilot.sh <main pid> <main attempt> <final analysis script> <pilot attempt> <pilot protocol sha256> <approval>
set -u
main_pid="$1"; main="$2"; analysis="$3"; pilot="$4"; sha="$5"; approval="$6"
cd "$(dirname "$0")" || exit 2
log="$pilot/chain.log"
echo "$(date -u +%FT%TZ) waiting for main pid $main_pid" >> "$log"
while kill -0 "$main_pid" 2>/dev/null; do sleep 15; done
result=$(ls -1 "$main"/phases/sessions/result-*.json 2>/dev/null | tail -1)
restore=$(ls -1 "$main"/phases/sink-restore/result-*.json 2>/dev/null | tail -1)
if [ -z "$result" ] || ! grep -q '"status": "passed"' "$result"; then
  echo "$(date -u +%FT%TZ) main sessions phase not passed ($result): pilot not started" >> "$log"; exit 1
fi
if [ -z "$restore" ] || ! grep -q '"status": "passed"' "$restore"; then
  echo "$(date -u +%FT%TZ) main Sink restore not passed ($restore): pilot not started" >> "$log"; exit 1
fi
echo "$(date -u +%FT%TZ) main passed; final analysis" >> "$log"
if ! bash "$analysis" >> "$log" 2>&1; then
  echo "$(date -u +%FT%TZ) final analysis failed (see analysis-final/); starting the pilot anyway" >> "$log"
fi
echo "$(date -u +%FT%TZ) starting the pilot" >> "$log"
exec /usr/bin/python3 -u run_session_netpilot.py --run-all --attempt "$pilot" --protocol-sha256 "$sha" \
  --approval "$approval" >> "$pilot/netpilot.log" 2>&1 < /dev/null
