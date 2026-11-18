#!/bin/bash
# After the silent-server benign batch and its pre-registered scoring: rebuild the base dataset with the batch's
# benign rows (base/20261117b), score the paper's Table V pool with and without them, the whole base, and the
# silent-listener cue over every run. Offline; the VM is powered off by then, so it uses all CPUs at nice 19.
#   ./final_base_sb.sh   (waits for chain_silentbenign.sh to end)
set -u
cd "$(dirname "$0")" || exit 2
SB=20261117T013400746805Z
O=base/20261117b
R="nice -n 19 /usr/bin/python3"
W="$R with_runs.py silentbenign=$SB --"
RUNS=main,tpilot,floods,triage,rest,silentbenign
log=runs/$SB/final_base_sb.log
echo "$(date -u +%FT%TZ) waiting for chain_silentbenign.sh" >> $log
while pgrep -f chain_silentbenign.sh >/dev/null; do sleep 60; done
[ -f runs/$SB/analysis.json ] || { echo "$(date -u +%FT%TZ) no analysis.json for the batch; stop" >> $log; exit 3; }
mkdir -p $O/table45
date -u +%FT%TZ > $O/started.txt
rc=0
$W build_base.py --out $O --runs $RUNS --spans 20s,80s > $O/build_base.log 2>&1 || rc=$?
echo "$(date -u +%FT%TZ) build_base exit $rc" >> $log
for pool in paper paper_sb base; do
  $W table45_session.py --pool $pool --base $O --out $O/table45 > $O/table45/$pool.log 2>&1
  r=$?; echo "$(date -u +%FT%TZ) table45 $pool exit $r" >> $log; [ $r -eq 0 ] || rc=$r
done
$W silent_server_check.py --runs $RUNS --kinds malware,benign,null --out $O/silent-server > $O/silent-server.log 2>&1
r=$?; echo "$(date -u +%FT%TZ) silent_server_check exit $r" >> $log; [ $r -eq 0 ] || rc=$r
$W silent_cue_crosstab.py --runs $RUNS --silent $O/silent-server --out $O/silent-server/crosstab.json > $O/silent-crosstab.log 2>&1
r=$?; echo "$(date -u +%FT%TZ) silent_cue_crosstab exit $r" >> $log; [ $r -eq 0 ] || rc=$r
(cd $O && sha256sum base_*.csv manifest.csv base.json table45/*.json > SHA256SUMS)
date -u +%FT%TZ > $O/finished.txt
echo "$(date -u +%FT%TZ) final_base_sb.sh exit $rc" >> $log
exit $rc
