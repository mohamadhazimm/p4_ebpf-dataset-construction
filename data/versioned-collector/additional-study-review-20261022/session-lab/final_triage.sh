#!/bin/bash
# Final offline analysis of the Triage cohort (runs alongside the rest collection: pinned to CPUs 8-11,20-23, nice 19).
set -e
cd /home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/session-lab
R="taskset -c 8-11,20-23 nice -n 19 /usr/bin/python3"
T=runs/20261116T153432251861Z
O=$T/analysis-final
mkdir -p $O
date -u +%FT%TZ > $O/started.txt
$R analyze_session_lab.py $T --features --keep-going > $O/analyze.log 2>&1
$R summarize_runs.py $T --json $O/summary.json > $O/summary.log 2>&1
$R compare_session_lab.py $T --out $O > $O/compare.log 2>&1
$R build_base.py --runs triage --out $O/base-triage --spans 20s,80s > $O/base-triage.log 2>&1
$R build_base.py --runs tpilot,triage --out $O/base-triage-families --spans 20s,80s > $O/base-triage-families.log 2>&1
date -u +%FT%TZ > $O/finished.txt
