#!/bin/bash
# After the network-active pilot finishes: analyse it (VM idle), apply the two tested guest-script edits that let
# flood_gen's pyexec stage the published load tools, freeze the flood batch and run it. The flood batch confirms
# the flood result on the busy-background machine (user approval 2026-11-16: "okay let's do that please").
#   chain_flood.sh <pilot pid> <pilot attempt> <scratch guest dir> <approval>
set -u
pilot_pid="$1"; pilot="$2"; sdir="$3"; approval="$4"
cd "$(dirname "$0")" || exit 2
log="chain_flood.log"
say() { echo "$(date -u +%FT%TZ) $*" >> "$log"; }
say "waiting for pilot pid $pilot_pid"
while kill -0 "$pilot_pid" 2>/dev/null; do sleep 15; done
say "pilot process exited"

# analyse the pilot while the VM is idle (no analysis once the flood batch starts collecting)
if /usr/bin/python3 -u analyze_session_lab.py "$pilot" --features >> "$log" 2>&1 \
   && /usr/bin/python3 -u compare_session_lab.py "$pilot" --out "$pilot/analysis" >> "$log" 2>&1; then
  say "pilot analysed -> $pilot/analysis"
else
  say "pilot analysis failed (see $log); continuing to the flood batch"
fi

# apply the edited guest scripts (only if the live files are the known originals they were based on)
ORIG_ENTER=7ce2a2cf02a1d0c7; ORIG_SESSION=68cee504792261ad
le=$(sha256sum guest/enter.sh | cut -c1-16); ls=$(sha256sum guest/session.sh | cut -c1-16)
if [ "$le" != "$ORIG_ENTER" ] || [ "$ls" != "$ORIG_SESSION" ]; then
  say "live guest files are not the expected originals (enter $le session $ls); NOT editing, NOT running"; exit 3
fi
bak="guest/pre-flood-backup-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$bak"
cp -p guest/enter.sh guest/session.sh "$bak/" || { say "backup failed"; exit 3; }
cp -p "$sdir/guest/enter.sh" guest/enter.sh && cp -p "$sdir/guest/session.sh" guest/session.sh || { say "copy edited failed"; exit 3; }
bash -n guest/enter.sh && bash -n guest/session.sh || { say "edited guest syntax error"; exit 3; }
say "guest scripts edited (backup $bak): enter $(sha256sum guest/enter.sh|cut -c1-16) session $(sha256sum guest/session.sh|cut -c1-16)"

# the edits must not break the normal (archive / none) paths or the pyexec path
if ! /usr/bin/python3 -u run_session_lab.py --self-test >> "$log" 2>&1; then
  say "run_session_lab self-test failed after the edit; restoring originals and stopping"
  cp -p "$bak/enter.sh" guest/enter.sh; cp -p "$bak/session.sh" guest/session.sh; exit 4
fi
say "self-test passed"

# freeze and launch
freeze=$(/usr/bin/python3 -u run_session_flood.py --freeze-only 2>> "$log")
echo "$freeze" >> "$log"
attempt=$(/usr/bin/python3 -c "import json,sys;print(json.loads(sys.argv[1])['attempt'])" "$freeze")
sha=$(/usr/bin/python3 -c "import json,sys;print(json.loads(sys.argv[1])['protocol_sha256'])" "$freeze")
if [ -z "$attempt" ] || [ -z "$sha" ]; then say "freeze failed"; exit 5; fi
say "frozen $attempt sha $sha; launching the flood batch"
exec /usr/bin/python3 -u run_session_flood.py --run-all --attempt "$attempt" --protocol-sha256 "$sha" \
  --approval "$approval" >> "${attempt}.log" 2>&1 < /dev/null
