#!/usr/bin/env python3
"""Full dataset audit of the already-collected .21 runs outside the paper's 99 (offline, no VM).

The per-case audit is the one the 99 passed, unchanged: collect_v21.audit_case_v21 with the
revision5 settings contract (installed .21 runner hash in run.json, schema, fixed observation,
0.5-s windows, eBPF; accepted quality, exact target exec, native mode/linkage, 40x169 finite,
safe archive hashes, PCAP == received == captured, zero kernel drops, capture probes outside the
windows, unique recorded-window P4 alignment with Ethernet/nominal parity, traffic gate for nulls).

Runs audited:
  - C2 probe 20261025T142642347649Z: 18 malware + 9 nulls (all cases);
  - backdoor probe 20261025T151638248361Z: 20 malware + 6 nulls (all cases);
  - v21 collection 20261024T194347772138Z: the malware outside the 105 matched-selection samples
    plus its 9 nulls. These were audited before; the result must reproduce the saved report.

verify_plan() is replaced by the same plan checks minus verify_production(): src/ holds the .22
runner on purpose since 2026-11-05, and each run's own runner hash is checked per case.

Run: /usr/bin/python3 -I audit_extension.py   (the user site is added explicitly for scapy)
"""
import collections
import json
import pathlib
import site
import sys
import time

sys.path.append(site.getusersitepackages())
HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent  # additional-study-review-20261022
sys.path.insert(0, str(ROOT))
import collect_v21 as v21  # noqa: E402

frozen = v21.frozen
digest = getattr(v21, "digest", frozen.digest)
load = getattr(v21, "load", frozen.load)
require = getattr(v21, "require", frozen.require)

R5 = ("revision5-collection/20261025T100025568989Z", "a5e288835793ccb535387b8c5590e728e88de50096face496df0d514e8fee688")
ATTEMPTS = [
    ("C2 probe", "c2-viability/20261025T142642347649Z",
     "0e3908eb43b4d1c951b7ae1996610cdfbbb481565cb58f1472d4e1660752e7b5", "c2_selection.json"),
    ("backdoor probe", "evasive-viability/20261025T151638248361Z",
     "2ffb876bb3f33e848c424492ea7ccefc418d9b02da4784327ff4c20a49326cf0", "evasive_selection.json"),
    ("v21 collection", "v21-collection/20261024T194347772138Z",
     "5d6bda1d4209771c7f02978aebb7174192465676357fa61ba6d742aa00d05d89", None),
]
V21_SELECTION = ROOT / "v21-collection-selection/20261024T170741270302Z/malware_selection.json"
V21_REPORT = ROOT / "v21-collection/20261024T194347772138Z/validation-20261024T235509430027Z.json"
MATCHED = v21.STUDY / "data/malware/revision5-diverse/matched-selection/malware_selection.json"


def cases_of(d):
    return d["cases"] if isinstance(d, dict) else d


def verify(attempt, expected):
    path = ROOT / attempt / "protocol.json"
    require(digest(path) == expected, "Protocol hash differs: " + attempt)
    protocol = load(path)
    require(protocol["production_hashes"] == v21.PINNED, "Production pins differ: " + attempt)
    require(protocol["settings"] == v21.SETTINGS and protocol["schema"] == v21.SCHEMA
            and protocol["baseline_snapshot"] == v21.BASELINE, "Collection contract differs: " + attempt)
    for name, expected_file in protocol["files"].items():
        require(digest(ROOT / attempt / name) == expected_file, "Frozen plan file changed: %s/%s" % (attempt, name))
    return protocol


def main():
    started = time.time()
    settings = verify(*R5)["settings_required"]
    s105 = {c.get("member_sha256") or c.get("sha256") for c in cases_of(load(MATCHED))}
    require(len(s105) == 105, "Matched selection is not 105 samples")

    family = {}
    for _, attempt, _, selection in ATTEMPTS:
        source = ROOT / attempt / selection if selection else V21_SELECTION
        for c in cases_of(load(source)):
            family[c["member_sha256"]] = c["family"]

    def sha_for(case):
        if case.get("member_sha256"):
            return case["member_sha256"]
        hits = [s for s in family if s in case["sample"]]
        require(len(hits) == 1, "Cannot map sample to a selection entry: " + case["sample"])
        return hits[0]

    tools = frozen.validation_tools()
    saved_v21 = {r["sample"]: r for r in load(V21_REPORT)["results"]}
    rows, reproduction = [], {"compared": 0, "status_matches": 0, "reason_matches": 0, "differences": []}
    plan_hashes = {}
    for name, attempt, expected, _ in ATTEMPTS:
        protocol = verify(attempt, expected)
        plan_hashes[attempt] = expected
        for case in protocol["cases"]:
            sha = sha_for(case) if case["label"] == "malware" else None
            if name == "v21 collection" and case["label"] == "malware" and sha in s105:
                continue  # already in the matched selection: not an extension candidate
            if case["label"] not in ("malware", "null"):
                continue  # v21 benign: not part of this audit
            row = {"batch": name, "sample": case["sample"], "label": case["label"], "mode": case["mode"],
                   "family": family.get(sha) if sha else None, "member_sha256": sha}
            sample_dir = ROOT / attempt / "runs" / case["sample"]
            paths = list((sample_dir / "output").glob("run_*/run.json")) if sample_dir.exists() else []
            if len(paths) == 1:
                metadata = load(paths[0])
                row.update(return_code=metadata.get("return_code"),
                           quality_status=metadata.get("collection_quality_status"),
                           exec_status=metadata.get("target_exec", {}).get("status"))
            try:
                row.update(v21.audit_case_v21(sample_dir, case, settings, tools), status="accepted")
            except Exception as error:  # same handling as the dataset validation
                row.update(status="excluded", reason=type(error).__name__ + ": " + str(error))
            if name == "v21 collection":
                old = saved_v21[case["sample"]]
                reproduction["compared"] += 1
                reproduction["status_matches"] += old["status"] == row["status"]
                reproduction["reason_matches"] += old.get("reason") == row.get("reason")
                if old["status"] != row["status"] or old.get("reason") != row.get("reason"):
                    reproduction["differences"].append({"sample": case["sample"], "saved": old["status"],
                                                        "saved_reason": old.get("reason"), "now": row["status"],
                                                        "now_reason": row.get("reason")})
            rows.append(row)

    malware = [r for r in rows if r["label"] == "malware"]
    accepted = [r for r in malware if r["status"] == "accepted"]
    require(len({r["member_sha256"] for r in malware}) == len(malware), "Duplicate malware identity")
    require(not ({r["member_sha256"] for r in malware} & s105), "Overlap with the matched selection")

    by_family = collections.defaultdict(lambda: {"runs": 0, "accepted": 0, "modes": collections.Counter(), "batches": set()})
    for r in malware:
        e = by_family[r["family"]]
        e["runs"] += 1
        e["accepted"] += r["status"] == "accepted"
        if r["status"] == "accepted":
            e["modes"][r["mode"]] += 1
        e["batches"].add(r["batch"])
    nulls = collections.defaultdict(lambda: {"runs": 0, "accepted": 0, "max_post_target_syscalls": {}})
    for r in rows:
        if r["label"] != "null":
            continue
        e = nulls[r["batch"]]
        e["runs"] += 1
        e["accepted"] += r["status"] == "accepted"
        if r["status"] == "accepted":
            e["max_post_target_syscalls"][r["mode"]] = max(e["max_post_target_syscalls"].get(r["mode"], 0),
                                                           r["post_target_lineage_raw_syscalls"])

    summary = {
        "status": "offline_audited_no_merge_no_model",
        "settings_required": settings, "revision5_protocol_sha256": R5[1], "plan_protocol_sha256": plan_hashes,
        "malware": {"runs": len(malware), "accepted": len(accepted),
                    "excluded_reasons": dict(collections.Counter(r["reason"].split(":")[0] + ": " + r["reason"].split(": ", 1)[1].split(":")[0]
                                                                 for r in malware if r["status"] == "excluded"))},
        "by_family": {f: {"runs": e["runs"], "accepted": e["accepted"], "accepted_modes": dict(e["modes"]),
                          "batches": sorted(e["batches"])} for f, e in sorted(by_family.items())},
        "nulls": {b: dict(e) for b, e in nulls.items()},
        "v21_reproduction": reproduction,
        "results": rows,
        "auditor_sha256": digest(pathlib.Path(__file__)),
        "seconds": round(time.time() - started, 1),
        "collection_ready": False, "model_fits": 0, "merged_cases": 0,
    }
    out = HERE / ("extension_audit-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + ".json")
    out.write_text(json.dumps(summary, indent=1, default=list) + "\n")
    print(json.dumps({k: summary[k] for k in ("malware", "by_family", "nulls", "seconds")}, indent=1, default=list))
    print("v21 reproduction:", {k: v for k, v in reproduction.items() if k != "differences"},
          "differences:", reproduction["differences"])
    for r in malware:
        if r["status"] == "excluded":
            print("  excluded:", r["batch"], r["family"], r["mode"], "-", r["reason"][:140])
    print("report:", out)


if __name__ == "__main__":
    main()
