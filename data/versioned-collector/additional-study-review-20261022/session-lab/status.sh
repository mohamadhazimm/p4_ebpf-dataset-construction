#!/bin/bash
# Status of the session-lab main run: driver alive, sessions done/accepted, non-accepted list, last two, disk.
A=/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/session-lab/runs/20261115T214153675625Z
date -u +%T
pid=$(cat "$A/main.pid" 2>/dev/null)
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then echo "driver alive: yes"; else echo "driver alive: NO"; fi
/usr/bin/python3 - "$A" <<'PY'
import json, sys, glob, os
A = sys.argv[1]
rows = []
for f in sorted(glob.glob(os.path.join(A, "sessions", "*", "result.json"))):
    try:
        d = json.load(open(f))
    except Exception as e:
        rows.append(("?", "?", os.path.basename(os.path.dirname(f)), "unreadable", str(e))); continue
    why = ""
    if d.get("status") != "accepted":
        c = d.get("checks") or {}
        why = "; ".join(c.get("reasons", [])) if isinstance(c, dict) else ""
        if not why:
            fj = os.path.join(os.path.dirname(f), "failure.json")
            if os.path.exists(fj):
                try:
                    why = json.load(open(fj)).get("error", "")
                except Exception:
                    pass
    rows.append(((d.get("finished_utc") or "")[11:19], d.get("sid"), d.get("kind"), d.get("name"), d.get("status"), why))
acc = sum(1 for r in rows if r[4] == "accepted")
print("done: %d accepted: %d" % (len(rows), acc))
for r in rows:
    if r[4] != "accepted":
        print("%s %s %-8s %-24s %s %s" % (r[0], r[1], r[2], r[3], r[4], r[5][:200]))
for r in rows[-2:]:
    print("%s %s %-8s %-24s %s" % r[:5])
PY
df -h / | tail -1
