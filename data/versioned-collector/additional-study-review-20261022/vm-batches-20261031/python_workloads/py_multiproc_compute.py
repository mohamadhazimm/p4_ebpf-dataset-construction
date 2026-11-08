"""Benign parallel computation: 4 worker processes count primes in disjoint ranges."""
import json, sys
from multiprocessing import Pool
def primes(lo):
    hi, n = lo + 50000, 0
    for k in range(max(lo, 2), hi):
        if all(k % d for d in range(2, int(k ** 0.5) + 1)):
            n += 1
    return n
if __name__ == "__main__":
    with Pool(4) as pool:
        counts = pool.map(primes, [0, 50000, 100000, 150000])
    ok = sum(counts) == 17984
    print(json.dumps({"workload": "multiproc_compute", "ok": ok, "primes": sum(counts)}))
    sys.exit(0 if ok else 1)
