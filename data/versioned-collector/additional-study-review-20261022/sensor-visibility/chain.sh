#!/bin/bash
# Runs the frozen sensor-visibility attempt phase by phase; stops at the first failed phase.
#   chain.sh ATTEMPT_DIR PROTOCOL_SHA256 "VERBATIM APPROVAL"
set -uo pipefail
cd "$(dirname "$0")"
A="$1"; H="$2"; APPROVAL="$3"
for ph in preflight sink-check stage dry-run collect collect-b; do
  echo "=== $ph start $(date -u +%FT%TZ)"
  if ! /usr/bin/python3 collect_visibility.py --phase "$ph" --attempt "$A" --protocol-sha256 "$H" \
        --approval "$APPROVAL" >"$A/chain-$ph.log" 2>&1; then
    echo "=== FAILED $ph $(date -u +%FT%TZ)"; tail -5 "$A/chain-$ph.log"; exit 1
  fi
  echo "=== $ph passed $(date -u +%FT%TZ)"
done
/usr/bin/python3 collect_visibility.py --validate --attempt "$A" --protocol-sha256 "$H" >"$A/chain-validate.log" 2>&1 \
  || echo "=== validate failed"
/usr/bin/python3 collect_visibility.py --analyze --attempt "$A" --protocol-sha256 "$H" >"$A/chain-analyze.log" 2>&1 \
  || echo "=== analyze failed"
echo "=== done $(date -u +%FT%TZ)"
