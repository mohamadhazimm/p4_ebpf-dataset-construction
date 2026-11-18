#!/bin/bash
set -e
cd /home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/session-lab
R="nice -n 5 /usr/bin/python3"
O=analysis-final
mkdir -p $O
date -u +%T > $O/started.txt
$R analyze_session_lab.py runs/20261115T214153675625Z --features > $O/analyze-main.log 2>&1
$R summarize_runs.py runs/20261115T213142604626Z runs/20261115T214153675625Z --json $O/summary.json > $O/summary.log 2>&1
$R compare_session_lab.py runs/20261115T213142604626Z runs/20261115T214153675625Z --out $O > $O/compare.log 2>&1
$R tables_session_lab.py $O/summary.json $O/comparison.json > $O/tables.md
date -u +%T > $O/finished.txt
