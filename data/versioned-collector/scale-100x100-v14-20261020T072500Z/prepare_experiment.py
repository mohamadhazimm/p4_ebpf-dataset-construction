#!/usr/bin/env python3
import csv
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

EXPERIMENT = Path(__file__).resolve().parent
STUDY = EXPERIMENT.parents[2]
DATA = STUDY / "data"
SCHEMA = "2026-10-19.14"
EXPECTED_HASHES = {
    "runner": "b366c337481e82e3118038ac966f3b35d5a5195123213a763a5ba2a8b1bf09d9",
    "batch": "4490a4cec6e26307d1f3e00f28c09a07d6b8fdcfd8bc12a12961ee34f6887f9f",
    "staging": "5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103",
}
NETWORK = re.compile(
    r"(?i)(https?://|ftp://|/dev/tcp|\b(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|ftp|tftp|telnet|ping|host|dig)\b|\brsync\s+[^\n]*@)"
)
DESTRUCTIVE = re.compile(
    r"(?i)(\brm\s+-rf\b|\bmkfs(?:\.\w+)?\b|\b(?:reboot|shutdown|poweroff|halt)\b|\bsudo\b|\bdd\s+if=|\bmount\b|\bumount\b|\bchown\s+-R\b|\bchmod\s+777\b|/dev/(?:sd|nvme|vd)[a-z0-9]+)"
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def balanced(groups, limit):
    remaining = {key: list(values) for key, values in sorted(groups.items())}
    selected = []
    while len(selected) < limit:
        added = False
        for key in remaining:
            if remaining[key]:
                selected.append((key, remaining[key].pop(0)))
                added = True
                if len(selected) == limit:
                    break
        if not added:
            break
    if len(selected) != limit:
        raise SystemExit(f"Need {limit} candidates, found {len(selected)}")
    return selected


def write_manifest(path, values):
    path.write_text("".join(f"{value}\n" for value in values), encoding="utf-8")


def main():
    if any((EXPERIMENT / name).exists() for name in ("experiment_manifest.json", "selection.json")):
        raise SystemExit("Experiment manifests already exist; refusing to overwrite")

    source_paths = {
        "runner": STUDY / "src/malware_runner.py",
        "batch": STUDY / "scripts/vbox_malware_batch.sh",
        "staging": STUDY / "scripts/stage_versioned_runner_snapshot.sh",
    }
    actual_hashes = {name: sha256(path) for name, path in source_paths.items()}
    if actual_hashes != EXPECTED_HASHES:
        raise SystemExit(f"Source hash mismatch: {actual_hashes}")

    pilot_path = DATA / "versioned-collector/benign-training-pilot23-v14-20261020T064840Z/pilot23_results.json"
    pilot = json.loads(pilot_path.read_text(encoding="utf-8"))
    pilot_names = {row["sample"] for row in pilot["samples"]}
    if len(pilot_names) != 23 or pilot["sample_count"] != 23:
        raise SystemExit("Pilot exclusion set is not exactly 23 samples")

    benign_source = DATA / "benign/revision4/expanded/training/workload_scripts"
    benign_list = DATA / "versioned-collector/telemetry-2026-10-18.1-20261018T161354Z/manifests/benign-training-500.txt"
    benign_groups = defaultdict(list)
    audit_exclusions = {}
    for name in benign_list.read_text(encoding="utf-8").splitlines():
        if not name or name in pilot_names:
            continue
        path = benign_source / name
        if not path.is_file():
            audit_exclusions[name] = "missing_source"
            continue
        contents = path.read_text(encoding="utf-8", errors="replace")
        if NETWORK.search(contents):
            audit_exclusions[name] = "network_command_or_destination"
            continue
        if DESTRUCTIVE.search(contents):
            audit_exclusions[name] = "destructive_command"
            continue
        package = name.split("_")[2]
        benign_groups[package].append(name)
    benign_selected = balanced(benign_groups, 100)

    malware_source = DATA / "malware/full-cohort-323/samples"
    malware_manifest = DATA / "malware/full-cohort-323/cohort_manifest.csv"
    malware_groups = defaultdict(list)
    with malware_manifest.open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            name = row["sample_artifact"]
            path = malware_source / name
            if not path.is_file():
                raise SystemExit(f"Missing malware artifact: {path}")
            malware_groups[row["group_id"]].append((name, row["attack_type_label"]))
    for values in malware_groups.values():
        values.sort(key=lambda value: value[0])
    malware_selected = balanced(malware_groups, 100)

    manifests = EXPERIMENT / "manifests"
    manifests.mkdir(parents=True, exist_ok=True)
    benign_names = [name for _, name in benign_selected]
    malware_names = [name for _, (name, _) in malware_selected]
    write_manifest(manifests / "benign-100.txt", benign_names)
    write_manifest(manifests / "malware-100.txt", malware_names)

    benign_records = [
        {"sample": name, "family": family, "sha256": sha256(benign_source / name)}
        for family, name in benign_selected
    ]
    malware_records = [
        {
            "sample": name,
            "family": family,
            "attack_type_label": label,
            "sha256": sha256(malware_source / name),
        }
        for family, (name, label) in malware_selected
    ]
    selection = {
        "selection_policy": {
            "benign": "100 local-only scripts, round-robin by tool family; excludes exactly the 23 scripts in the immediately preceding pilot",
            "malware": "100 unique artifacts, round-robin by family from the 323-artifact source manifest",
            "historical_runs": "Only the 23 immediately preceding benign pilot items are excluded by the clarified no-repeat scope; prior historical cohort IDs may recur.",
        },
        "benign_pilot_exclusion": sorted(pilot_names),
        "benign_audit_exclusions": audit_exclusions,
        "benign": benign_records,
        "malware": malware_records,
    }
    (EXPERIMENT / "selection.json").write_text(json.dumps(selection, indent=2) + "\n", encoding="utf-8")

    now = datetime.now(timezone.utc).isoformat()
    manifest = {
        "run_id": EXPERIMENT.name,
        "created_at_utc": now,
        "schema_version": SCHEMA,
        "feature_count": 169,
        "runner_sha256": actual_hashes["runner"],
        "batch_script_sha256": actual_hashes["batch"],
        "staging_script_sha256": actual_hashes["staging"],
        "counts": {"malware": 100, "benign": 100},
        "snapshots": {
            "malware_baseline": "clean-current-runner-2026-10-18.1-malware",
            "malware_child": EXPERIMENT.name + "-malware",
            "benign_baseline": "clean-benign-expanded-20261017",
            "benign_child": EXPERIMENT.name + "-benign",
        },
        "guest_directories": {
            "malware": "/home/csci/Downloads/malware_full_cohort_323",
            "benign": "/home/csci/Downloads/benign-expanded/training/workload_scripts",
        },
        "settings": {
            "timeout_seconds": 20,
            "window_seconds": 0.5,
            "interface": "enp0s3",
            "ebpf": True,
            "fixed_observation": True,
            "common_launch_wrapper": True,
            "pcap_buffer_kib": 65536,
            "pcap_drain_ms": 1000,
            "bpftrace_perf_rb_pages": 16384,
            "network_policy": "isolated internal malnet only; no public networking",
        },
        "manifests": {
            "malware": "manifests/malware-100.txt",
            "malware_sha256": sha256(manifests / "malware-100.txt"),
            "benign": "manifests/benign-100.txt",
            "benign_sha256": sha256(manifests / "benign-100.txt"),
        },
        "status": "prepared_not_staged",
    }
    (EXPERIMENT / "experiment_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    if len(set(malware_names)) != 100 or len(set(benign_names)) != 100:
        raise SystemExit("Selection contains duplicate sample names")
    if set(benign_names) & pilot_names:
        raise SystemExit("Benign selection overlaps the 23-item pilot")
    print(f"Prepared {len(malware_names)} malware and {len(benign_names)} benign samples")
    print(f"Malware families: {len({family for family, _ in malware_selected})}")
    print(f"Benign families: {len({family for family, _ in benign_selected})}")
    print(f"Pilot overlap: {len(set(benign_names) & pilot_names)}")
    print(f"Benign safety exclusions: {len(audit_exclusions)}")
    print(f"Experiment root: {EXPERIMENT}")


if __name__ == "__main__":
    main()
