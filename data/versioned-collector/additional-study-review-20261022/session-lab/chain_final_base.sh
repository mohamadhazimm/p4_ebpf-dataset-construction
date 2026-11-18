#!/bin/bash
# Run final_base.sh once the rest collection's process has ended (offline analysis only).
cd "$(dirname "$0")" || exit 2
pid="$1"; log=runs/20261116T223142789936Z/chain_final_base.log
echo "$(date -u +%FT%TZ) waiting for rest pid $pid" >> $log
while kill -0 "$pid" 2>/dev/null; do sleep 30; done
echo "$(date -u +%FT%TZ) rest ended; final_base.sh" >> $log
./final_base.sh >> $log 2>&1; rc=$?; echo "$(date -u +%FT%TZ) final_base.sh exit $rc" >> $log
