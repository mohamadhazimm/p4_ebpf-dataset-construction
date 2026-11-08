"""Benign integrity check: create 200 files in a directory tree, hash each with SHA-256, write a manifest."""
import hashlib, json, os, sys
os.makedirs("tree", exist_ok=True)
for d in range(10):
    os.makedirs("tree/d%d" % d, exist_ok=True)
    for i in range(20):
        with open("tree/d%d/f%d.txt" % (d, i), "w") as f:
            f.write(("line %d of file %d in dir %d\n" % (0, i, d)) * (100 + 50 * i))
manifest = {}
for root, _, files in os.walk("tree"):
    for name in files:
        path = os.path.join(root, name)
        with open(path, "rb") as f:
            manifest[path] = hashlib.sha256(f.read()).hexdigest()
with open("manifest.json", "w") as f:
    json.dump(manifest, f, sort_keys=True)
print(json.dumps({"workload": "hash_tree", "ok": len(manifest) == 200, "files": len(manifest)}))
sys.exit(0 if len(manifest) == 200 else 1)
