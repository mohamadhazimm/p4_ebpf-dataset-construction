#!/usr/bin/env bash
# Run the frozen benign-rest 5-min collection once the bursty collection has finished and the VM is idle.
# Usage: chain_benign_rest.sh <rest-attempt-dir> <rest-protocol-sha256> "<verbatim user approval>"
# Waits for benign-bursty-5min/<attempt>/phases/collect/result.json, then 10 consecutive quiet minutes (no collector
# process, guest powered off), then preflight -> stage -> dry-run -> collect -> validate -> behavior-check, stopping at
# the first failed phase. Benign only; every phase restores the original snapshot on exit. Log: <attempt>/chain.log
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
ATT="$1"; SHA="$2"; APPROVAL="$3"
BURSTY="$ROOT/benign-bursty-5min/20261107T071120390917Z/phases/collect/result.json"
LOG="$ATT/chain.log"
log() { echo "$(date -u +%FT%TZ) $*" | tee -a "$LOG"; }
log "waiting for the bursty collection to finish: $BURSTY"
until [ -f "$BURSTY" ]; do sleep 60; done
log "bursty collect result present; waiting for 10 quiet minutes"
quiet=0
while [ "$quiet" -lt 10 ]; do
  sleep 60
  if pgrep -f "collect_|vbox_malware_batch|stage_versioned" >/dev/null; then quiet=0; continue; fi
  state="$(VBoxManage showvminfo Ubuntu-Clean-24.04 --machinereadable 2>/dev/null | grep '^VMState=' | cut -d= -f2)"
  if [ "$state" = '"poweroff"' ]; then quiet=$((quiet+1)); else quiet=0; fi
done
log "VM idle; starting the benign-rest phases"
for phase in preflight stage dry-run collect; do
  log "phase $phase"
  nice -n 10 /usr/bin/python3 "$ROOT/collect_benign_rest.py" --phase "$phase" --attempt "$ATT" --protocol-sha256 "$SHA" --approval "$APPROVAL" >> "$ATT/chain-$phase.log" 2>&1
  status="$(/usr/bin/python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['status'])" "$ATT/phases/$phase/result.json" 2>/dev/null)"
  log "phase $phase -> ${status:-no result}"
  [ "$status" = "passed" ] || { log "stopping at $phase"; exit 1; }
done
/usr/bin/python3 "$ROOT/collect_benign_rest.py" --validate --attempt "$ATT" --protocol-sha256 "$SHA" >> "$ATT/chain-validate.log" 2>&1
/usr/bin/python3 "$ROOT/collect_benign_rest.py" --behavior-check --attempt "$ATT" --protocol-sha256 "$SHA" >> "$ATT/chain-behavior.log" 2>&1
log "done"
