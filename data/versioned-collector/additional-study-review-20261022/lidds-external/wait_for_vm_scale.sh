#!/usr/bin/env bash
# Exit 0 once the other session's 5-minute scale collection has written its collect result, no
# collector, batch or stager process runs, and the malware VM is powered off, all for 10 consecutive
# checks a minute apart (a grace period in case that session starts a follow-up VM phase). Exit 3 after 14 h.
# (Replaces wait_for_vm.sh, which waited on the superseded pilot attempt.)
A=/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/scale-5min/20261105T224558731619Z
deadline=$(( $(date +%s) + 14*3600 )); ok=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  busy=$(pgrep -f 'collect_scale|collect_pilot|vbox_malware_batch|stage_versioned_runner|collect_lowrate21|collect_v21|collect_flood21' | wc -l)
  state=$(VBoxManage showvminfo Ubuntu-Clean-24.04 --machinereadable 2>/dev/null | grep '^VMState=' | cut -d'"' -f2)
  if [ -f "$A/phases/collect/result.json" ] && [ "$busy" -eq 0 ] && [ "$state" = "poweroff" ]; then
    ok=$((ok+1)); [ "$ok" -ge 10 ] && { echo "VM_FREE scale=$(head -c 300 $A/phases/collect/result.json)"; exit 0; }
  else
    ok=0
  fi
  sleep 60
done
echo "TIMEOUT"; exit 3
