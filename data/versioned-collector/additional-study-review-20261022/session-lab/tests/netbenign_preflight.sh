#!/bin/bash
# Host preflight of the network-active benign batch: every task once, in an unprivileged loopback-only network
# namespace, against stand-in servers and the real transport test server. Nothing leaves the namespace.
#   tests/netbenign_preflight.sh <out-dir>
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
lab="$(dirname "$here")"
asr="$(dirname "$lab")"
out="$(mkdir -p "$1" && cd "$1" && pwd)"
rm -rf "$out/bins" "$out/tools" "$out/work" "$out/standin.jsonl" "$out/standin.ready"
mkdir -p "$out/bins" "$out/tools"
# the batch's task list (specs, not a frozen protocol) and its archives
/usr/bin/python3 - "$out" <<'EOF'
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[0]).resolve().parent) if False else ".")
EOF
( cd "$lab" && /usr/bin/python3 -c '
import json, sys
from pathlib import Path
import run_session_netbenign as N
out = Path(sys.argv[1])
N.build_samples(out / "samples")
json.dump({"sessions": N.specs()}, open(out / "specs.json", "w"), indent=1)
' "$out" )
for z in "$out"/samples/*.zip; do
  d="$out/bins/$(basename "$z" .zip)"
  mkdir -p "$d" && 7z x -pinfected -o"$d" -y "$z" > /dev/null && chmod 755 "$d"/*
done
cp "$asr/flood_gen" "$out/tools/webfetch"; cp "$asr/lowrate_gen" "$out/tools/netpoll"
cp "$asr/transport21/transport_client.py" "$out/tools/"
chmod 755 "$out/tools/webfetch" "$out/tools/netpoll"
[ -f "$out/cert.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout "$out/key.pem" -out "$out/cert.pem" \
  -days 2 -subj /CN=stand-in > /dev/null 2>&1
LT="$out/bins/labtransport-client/labtransport"
unshare -rn bash -c "
  set -u
  ip link set lo up
  ip addr add 10.0.0.1/32 dev lo
  ip addr add 203.0.113.1/24 dev lo
  ip addr add 198.51.100.1/24 dev lo
  ip addr add 192.0.2.1/24 dev lo
  /usr/bin/python3 -I '$here/netbenign_preflight.py' --serve --out '$out' > '$out/standin.out' 2>&1 &
  S=\$!
  '$LT' server -addr 10.0.0.1 > '$out/testserver.log' 2>&1 &
  L=\$!
  for i in \$(seq 50); do [ -f '$out/standin.ready' ] && break; sleep 0.2; done
  sleep 2
  /usr/bin/python3 -I '$here/netbenign_preflight.py' --run --out '$out' --protocol '$out/specs.json' \
     --bins '$out/bins' --tools '$out/tools'
  rc=\$?
  kill \$S \$L 2>/dev/null
  exit \$rc
"
