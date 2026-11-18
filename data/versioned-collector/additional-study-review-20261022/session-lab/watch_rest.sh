#!/bin/bash
# Watch the rest run: exit (and so notify) when its process ends, or when rest.log gets no new line for STALL_S.
#   watch_rest.sh <rest attempt> [stall seconds, default 1200]
R="$1"; STALL_S="${2:-1200}"
cd "$(dirname "$0")" || exit 2
pid=$(pgrep -f 'run_session_rest.py --run-all' | head -1)
[ -n "$pid" ] || { echo "no rest process"; exit 1; }
echo "$(date -u +%FT%TZ) watching pid $pid"
while kill -0 "$pid" 2>/dev/null; do
  sleep 60
  age=$(( $(date +%s) - $(stat -c %Y "$R/rest.log") ))
  if [ "$age" -gt "$STALL_S" ]; then echo "$(date -u +%FT%TZ) STALL: rest.log unchanged for ${age} s"; break; fi
done
kill -0 "$pid" 2>/dev/null && echo "process still alive (stall)" || echo "$(date -u +%FT%TZ) rest process ended"
grep -cE ' accepted' "$R/rest.log" | sed 's/^/accepted lines: /'
tail -n 6 "$R/rest.log"
