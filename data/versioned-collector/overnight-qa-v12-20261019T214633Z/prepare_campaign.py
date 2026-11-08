import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
COHORT = STUDY / "data/malware/full-cohort-323/cohort_manifest.csv"
FAMILY_AUDIT = STUDY / "data/versioned-collector/family-loss-monitor-v8-20261019T152933Z"
RECENT_QA = STUDY / "data/versioned-collector/malware-pcap-counter-qa-v12-20261019T203011Z"
BENIGN_TOOLS = ("ping", "openssl", "vmstat", "tail", "md5sum", "dd", "find", "tar", "curl", "wget")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    prior_selection = json.loads((FAMILY_AUDIT / "family_selection.json").read_text())
    prior_results = json.loads((FAMILY_AUDIT / "loss_monitor_results.json").read_text())["results"]
    recent_selection = json.loads((RECENT_QA / "selection.json").read_text())
    recent_artifacts = {item["artifact"] for item in recent_selection["samples"]}
    prior_retrieved = {item["sample"] for item in prior_results if item["retrieval_status"] == "completed"}
    prior_gaps = {item["sample"]: item["received_minus_captured"] for item in prior_results}
    excluded_archive_failure = "3fafbee7a3b7259db3cb16b1ea7ebf7c12a61ced08e8f71c5e85258090d8b6cf.zip"

    candidates = defaultdict(list)
    with COHORT.open(newline="") as source:
        for row in csv.DictReader(source):
            family = row["group_id"].split("::")[-1]
            artifact = row["sample_artifact"]
            if family in {"unassigned", "JackSkid"}:
                continue
            if artifact in recent_artifacts or artifact == excluded_archive_failure:
                continue
            if row["sample_status"] == "runtime_dependency_missing":
                continue
            candidates[family].append({
                "artifact": artifact,
                "source_cohort": row["source_cohort"],
                "group_id": row["group_id"],
                "prior_cohort_status": row["sample_status"],
                "prior_v8_retrieval_completed": artifact in prior_retrieved,
                "prior_v8_received_capture_gap": prior_gaps.get(artifact),
            })

    for family, items in candidates.items():
        items.sort(key=lambda item: (
            not item["prior_v8_retrieval_completed"],
            item["prior_cohort_status"] != "completed",
            item["artifact"],
        ))

    families = sorted(candidates)
    selected = []
    rank = 0
    while len(selected) < 100:
        added = False
        for family in families:
            if rank < len(candidates[family]):
                selected.append({"family": family, **candidates[family][rank]})
                added = True
                if len(selected) == 100:
                    break
        if not added:
            break
        rank += 1
    if len(selected) != 100:
        raise SystemExit(f"Expected 100 eligible artifacts, found {len(selected)}")

    waves = [selected[:50], selected[50:]]
    if len({item["family"] for item in waves[0]}) < 20:
        raise SystemExit("Wave 1 must span at least 20 named families")
    if len({item["family"] for item in waves[1]}) < 8:
        raise SystemExit("Wave 2 must span at least 8 named families")
    artifact_names = [item["artifact"] for item in selected]
    if len(set(artifact_names)) != len(artifact_names):
        raise SystemExit("Selected malware artifacts are not unique")

    manifests = ROOT / "manifests"
    manifests.mkdir(parents=True, exist_ok=True)
    for wave_number, wave in enumerate(waves, 1):
        all_path = manifests / f"malware-wave-{wave_number}-all.txt"
        all_path.write_text("".join(f"{item['artifact']}\n" for item in wave), encoding="utf-8")
        for round_number in range(5):
            chunk = wave[round_number * 10:(round_number + 1) * 10]
            path = manifests / f"malware-wave-{wave_number}-round-{round_number + 1:02d}.txt"
            path.write_text("".join(f"{item['artifact']}\n" for item in chunk), encoding="utf-8")

    (manifests / "benign-10.txt").write_text("".join(f"{name}\n" for name in BENIGN_TOOLS), encoding="utf-8")
    report = {
        "selection_method": "Deterministic round-robin across all eligible named families, preferring prior retrieval-complete candidates and prior completed processes.",
        "source_cohort": "data/malware/full-cohort-323/cohort_manifest.csv",
        "source_cohort_sha256": sha256(COHORT),
        "source_v8_audit": "data/versioned-collector/family-loss-monitor-v8-20261019T152933Z/",
        "source_v8_family_selection_sha256": sha256(FAMILY_AUDIT / "family_selection.json"),
        "source_v8_results_sha256": sha256(FAMILY_AUDIT / "loss_monitor_results.json"),
        "recent_v12_artifacts_excluded": sorted(recent_artifacts),
        "known_jackskid_archive_failure_excluded": excluded_archive_failure,
        "excluded_families": ["unassigned", "JackSkid"],
        "runtime_dependency_missing_excluded": True,
        "malware_unique_artifacts": 100,
        "malware_families": sorted({item["family"] for item in selected}),
        "waves": [
            {
                "wave": wave_number,
                "sample_count": len(wave),
                "families": sorted({item["family"] for item in wave}),
                "samples": wave,
            }
            for wave_number, wave in enumerate(waves, 1)
        ],
        "benign": {
            "execution_count": 100,
            "unique_native_elf_controls": list(BENIGN_TOOLS),
            "profiles": [f"profile-{number:02d}" for number in range(1, 11)],
            "execution_unit_note": "100 benign workload runs across 10 distinct preflighted native ELF tools; each tool is exercised under 10 profiles, so this is not 100 unique binaries.",
        },
    }
    (ROOT / "selection.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "malware_unique_artifacts": report["malware_unique_artifacts"],
        "malware_family_count": len(report["malware_families"]),
        "wave1_family_count": len(report["waves"][0]["families"]),
        "wave2_family_count": len(report["waves"][1]["families"]),
        "benign_runs": report["benign"]["execution_count"],
        "benign_unique_native_tools": len(BENIGN_TOOLS),
        "wave1_repeated_from_v8": sum(item["prior_v8_retrieval_completed"] for item in waves[0]),
        "wave2_repeated_from_v8": sum(item["prior_v8_retrieval_completed"] for item in waves[1]),
    }, indent=2))


if __name__ == "__main__":
    main()