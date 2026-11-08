"""Targeted controlled-C2 flood run of 3 RE-selected candidates, reusing the tested
probe_net_strong_viability engine UNCHANGED (freeze/run_campaign/_one/controller).
Only the sample selection is overridden in-process to our exact SHAs + RE'd C2.
Reg-only controller (NO attack command); sealed malnet; BASELINE restore+poweroff per sample.
Usage: python3 run_retarget_floods.py            # freeze
       python3 run_retarget_floods.py --run --attempt <dir> --approval "<verbatim>"
"""
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import probe_net_strong_viability as eng   # noqa: E402

# RE triage picks (scratchpad/re_triage.json): sha-prefix, kind, RE'd clean C2 IPs
TARGETS = [
    ("0da7cb37eb", "malware_c2", ["91.92.252.34"]),   # Tsunami amd64-static, IRC + auto-scan (best)
    ("15b4e2421206", "malware_c2", ["193.143.1.118"]),  # Tsunami amd64-static, IRC command-driven, real C2
    ("160b29be7a24", "malware", None),                # Mirai amd64-static, autonomous (binary C2 opaque)
]


def targeted_select(_per_family):
    man = json.load(open(eng.MANIFEST))["kept"]
    by = {r["sha256"]: r for r in man}
    out = []
    for pfx, kind, ips in TARGETS:
        hits = [r for r in man if r["sha256"].startswith(pfx)]
        if len(hits) != 1:
            raise SystemExit("prefix %s -> %d matches" % (pfx, len(hits)))
        r = hits[0]
        d = {"name": (("c2_" if kind == "malware_c2" else "mirai_") + r["sha256"][:10]),
             "kind": kind, "sha256": r["sha256"], "family": r["family"], "mode": r["mode"]}
        if kind == "malware_c2":
            d["c2_ips"] = ips
        out.append(d)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--attempt")
    ap.add_argument("--approval")
    a = ap.parse_args()
    if a.run:
        eng.run_campaign(a.attempt, a.approval)
    else:
        eng.select = targeted_select            # override selection only; freeze() + packaging unchanged
        eng.freeze(per_family=3, tag="retarget-re", source="mb")


if __name__ == "__main__":
    main()
