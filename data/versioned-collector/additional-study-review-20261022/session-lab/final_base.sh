#!/bin/bash
# After the rest run: analyse it, then build and score the base dataset from every session-lab run under the main
# settings, and compare the dataset's programs (main + rest) with their dataset rows. Offline. Runs only after the
# rest collection has ended (the VM is then powered off), so it uses all CPUs at nice 19 instead of the 8 CPUs the
# analyses used while a collection was running; the base build and the comparison are independent and run in parallel.
set -e
cd /home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/session-lab
R="nice -n 19 /usr/bin/python3"
REST=runs/20261116T223142789936Z
O=base/20261117
mkdir -p $O $REST/analysis-final
date -u +%FT%TZ > $O/started.txt
$R analyze_session_lab.py $REST --features --keep-going > $REST/analysis-final/analyze.log 2>&1
$R summarize_runs.py $REST --json $REST/analysis-final/summary.json > $REST/analysis-final/summary.log 2>&1
$R build_base.py --out $O --runs main,tpilot,floods,triage,rest --spans 20s,80s > $O/build_base.log 2>&1 &
b=$!
$R compare_session_lab.py runs/20261115T214153675625Z $REST --out $O/dataset-programs > $O/dataset-programs.log 2>&1 &
c=$!
rc=0
wait $b || rc=$?
wait $c || rc=$((rc ? rc : $?))
$R silent_server_check.py --runs main,tpilot,floods,triage,rest --kinds malware,benign,null --out $O/silent-server > $O/silent-server.log 2>&1 || rc=$((rc ? rc : $?))
$R silent_cue_crosstab.py --runs main,tpilot,floods,triage,rest --silent $O/silent-server --out $O/silent-server/crosstab.json > $O/silent-crosstab.log 2>&1 || rc=$((rc ? rc : $?))
(cd $O && sha256sum base_*.csv manifest.csv base.json > SHA256SUMS)
date -u +%FT%TZ > $O/finished.txt
exit $rc
