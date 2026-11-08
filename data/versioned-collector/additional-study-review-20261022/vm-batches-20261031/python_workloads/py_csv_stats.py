"""Benign report: write a 100,000-row CSV file, read it back, and compute per-region statistics."""
import csv, json, random, statistics, sys
random.seed(4)
with open("sales.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["region", "amount"])
    for i in range(100000):
        w.writerow(["r%d" % (i % 12), "%.2f" % random.gauss(100, 15)])
by = {}
with open("sales.csv", newline="") as f:
    for row in csv.DictReader(f):
        by.setdefault(row["region"], []).append(float(row["amount"]))
report = {k: {"mean": statistics.fmean(v), "stdev": statistics.stdev(v)} for k, v in by.items()}
with open("report.json", "w") as f:
    json.dump(report, f)
print(json.dumps({"workload": "csv_stats", "ok": len(report) == 12}))
sys.exit(0 if len(report) == 12 else 1)
