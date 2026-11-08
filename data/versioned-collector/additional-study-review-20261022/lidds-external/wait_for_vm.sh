#!/usr/bin/env bash
# Exit 0 once the 5-minute pilot's collect phase has finished, no collector, batch or stager process
# runs, and the malware VM is powered off (checked twice, a minute apart). Exit 3 after 14 hours.
P=/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/pilot-5min/20261105T195206286366Z
deadline=$(( $(date +%s) + 14*3600 )); ok=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  busy=$(pgrep -f 'collect_pilot|vbox_malware_batch|stage_versioned_runner|collect_lowrate21|collect_v21|collect_flood21' | wc -l)
  state=$(VBoxManage showvminfo Ubuntu-Clean-24.04 --machinereadable 2>/dev/null | grep '^VMState=' | cut -d'"' -f2)
  if [ -f "$P/phases/collect/result.json" ] && [ "$busy" -eq 0 ] && [ "$state" = "poweroff" ]; then
    ok=$((ok+1)); [ "$ok" -ge 2 ] && { echo "VM_FREE pilot=$(cat $P/phases/collect/result.json | head -c 300)"; exit 0; }
  else
    ok=0
  fi
  sleep 60
done
echo "TIMEOUT"; exit 3
