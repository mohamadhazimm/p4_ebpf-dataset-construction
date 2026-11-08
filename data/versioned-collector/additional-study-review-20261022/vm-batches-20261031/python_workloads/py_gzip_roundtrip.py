"""Benign compression: write 24 MiB of semi-random data, gzip it, decompress it, and compare digests."""
import gzip, hashlib, json, random, sys
random.seed(2)
words = [bytes(random.choice(b"abcdefghij") for _ in range(8)) for _ in range(512)]
h = hashlib.sha256()
with open("data.bin", "wb") as f:
    for _ in range(24 * 64):
        block = b" ".join(random.choice(words) for _ in range(1820))[:16384]
        f.write(block); h.update(block)
with open("data.bin", "rb") as src, gzip.open("data.bin.gz", "wb") as dst:
    while chunk := src.read(65536):
        dst.write(chunk)
h2 = hashlib.sha256()
with gzip.open("data.bin.gz", "rb") as f:
    while chunk := f.read(65536):
        h2.update(chunk)
ok = h.digest() == h2.digest()
print(json.dumps({"workload": "gzip_roundtrip", "ok": ok}))
sys.exit(0 if ok else 1)
