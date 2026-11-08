"""Benign data transform: build 50,000 records, serialize to JSON lines, read back and aggregate."""
import json, random, sys
random.seed(1)
with open("records.jsonl", "w") as f:
    for i in range(50000):
        f.write(json.dumps({"id": i, "user": "u%d" % (i % 997), "value": random.random(), "tags": ["a", "b"][: i % 3]}) + "\n")
totals = {}
with open("records.jsonl") as f:
    for line in f:
        r = json.loads(line)
        totals[r["user"]] = totals.get(r["user"], 0.0) + r["value"]
with open("totals.json", "w") as f:
    json.dump(totals, f)
print(json.dumps({"workload": "json_transform", "ok": len(totals) == 997, "users": len(totals)}))
sys.exit(0 if len(totals) == 997 else 1)
