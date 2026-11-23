#!/bin/bash
# Session lab with real internet: no generated background. The process in cgroup app-a only waits for the
# session's length, so the lab adds no traffic of its own; the injected program's traffic is the only traffic it
# starts. Same arguments as the isolated lab's bg.sh: <seed> <duration s> <tools dir> <work dir> [scale per mille].
set -u
dur="$2"; work="$4"
cd "$work" || exit 2
echo "$EPOCHREALTIME background none duration_s $dur" >> "$work/bg.log"
sleep "$dur"
echo "$EPOCHREALTIME schedule done" >> "$work/bg.log"
