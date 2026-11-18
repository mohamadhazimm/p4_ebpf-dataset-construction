#!/bin/bash
# After the network-active benign batch and its analysis: the pre-registered scoring, the base rebuilt with the batch
# (base/20261117c), Table V format for the paper pool and the whole base, and the silent-listener cue over every run.
# Called by chain_netbenign.sh; uses all CPUs at nice 19 (the VM is powered off by then).
#   ./final_netbenign.sh runs/<batch>
set -u
cd "$(dirname "$0")" || exit 2
A=$1
N=$(basename $A)
SB=20261117T013400746805Z
O=base/20261117c
R="nice -n 19 /usr/bin/python3"
W="$R with_runs.py silentbenign=$SB netbenign=$N --"
RUNS=main,tpilot,floods,triage,rest,silentbenign,netbenign
[ -f $A/analysis.json ] || { echo "$(date -u +%FT%TZ) no analysis.json; stop"; exit 3; }
rc=0
$R check_netbenign_behaviour.py $A > $A/analysis/behaviour.log 2>&1
r=$?; echo "$(date -u +%FT%TZ) behaviour check exit $r"; [ $r -eq 0 ] || rc=$r
$R score_netbenign.py --attempt $A --out $A/analysis > $A/analysis/score.log 2>&1
r=$?; echo "$(date -u +%FT%TZ) score_netbenign exit $r"; [ $r -eq 0 ] || rc=$r
mkdir -p $O/table45
date -u +%FT%TZ > $O/started.txt
$W build_base.py --out $O --runs $RUNS --spans 20s,80s > $O/build_base.log 2>&1
r=$?; echo "$(date -u +%FT%TZ) build_base exit $r"; [ $r -eq 0 ] || rc=$r
for pool in paper_sb_nb base; do
  $W table45_session.py --pool $pool --base $O --out $O/table45 > $O/table45/$pool.log 2>&1
  r=$?; echo "$(date -u +%FT%TZ) table45 $pool exit $r"; [ $r -eq 0 ] || rc=$r
done
$W silent_server_check.py --runs $RUNS --kinds malware,benign,null --out $O/silent-server > $O/silent-server.log 2>&1
r=$?; echo "$(date -u +%FT%TZ) silent_server_check exit $r"; [ $r -eq 0 ] || rc=$r
$W silent_cue_crosstab.py --runs $RUNS --silent $O/silent-server --out $O/silent-server/crosstab.json > $O/silent-crosstab.log 2>&1
r=$?; echo "$(date -u +%FT%TZ) silent_cue_crosstab exit $r"; [ $r -eq 0 ] || rc=$r
(cd $O && sha256sum base_*.csv manifest.csv base.json table45/*.json > SHA256SUMS)
date -u +%FT%TZ > $O/finished.txt
echo "$(date -u +%FT%TZ) final_netbenign.sh exit $rc"
exit $rc
