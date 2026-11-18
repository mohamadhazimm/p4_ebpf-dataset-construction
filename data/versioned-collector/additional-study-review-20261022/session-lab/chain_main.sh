#!/bin/bash
# Start the main collection after the pilot, only if the pilot's session phase passed (every session accepted).
#   chain_main.sh <pilot pid> <pilot attempt> <main attempt> <main protocol sha256> <deadline UTC> <approval>
set -u
pilot_pid="$1"; pilot="$2"; main="$3"; sha="$4"; deadline="$5"; approval="$6"
cd "$(dirname "$0")" || exit 2
log="$main/chain.log"
echo "$(date -u +%FT%TZ) waiting for pilot pid $pilot_pid" >> "$log"
while kill -0 "$pilot_pid" 2>/dev/null; do sleep 15; done
result=$(ls -1 "$pilot"/phases/sessions/result-*.json 2>/dev/null | tail -1)
if [ -z "$result" ] || ! grep -q '"status": "passed"' "$result"; then
  echo "$(date -u +%FT%TZ) pilot sessions phase not passed ($result): main not started" >> "$log"
  exit 1
fi
restore=$(ls -1 "$pilot"/phases/sink-restore/result-*.json 2>/dev/null | tail -1)
if [ -z "$restore" ] || ! grep -q '"status": "passed"' "$restore"; then
  echo "$(date -u +%FT%TZ) pilot Sink restore not passed ($restore): main not started" >> "$log"
  exit 1
fi
echo "$(date -u +%FT%TZ) pilot passed; starting main (deadline $deadline)" >> "$log"
exec /usr/bin/python3 -u run_session_main.py --run-all --attempt "$main" --protocol-sha256 "$sha" \
  --approval "$approval" --deadline-utc "$deadline" >> "$main/main.log" 2>&1 < /dev/null
