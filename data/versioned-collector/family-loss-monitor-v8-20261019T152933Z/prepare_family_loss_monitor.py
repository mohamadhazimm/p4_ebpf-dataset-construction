import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
WORKSPACE = STUDY.parents[1]
COHORT_CSV = STUDY / "data/malware/full-cohort-323/cohort_manifest.csv"
FAMILY_SMOKE = STUDY / "data/versioned-collector/runner-v4-family-smoke-20261019T130151Z/experiment_manifest.json"
LOCKBIT_EXPERIMENT = STUDY / "data/versioned-collector/lockbit-v8-recheck-20261019T151547Z/experiment_manifest.json"
LOCKBIT_RESULTS = STUDY / "data/versioned-collector/lockbit-v8-recheck-20261019T151547Z/lockbit_v8_results.json"
RUNNER = STUDY / "src/malware_runner.py"
BATCH = STUDY / "scripts/vbox_malware_batch.sh"
STAGING = STUDY / "scripts/stage_versioned_runner_snapshot.sh"
HIGH_SYSCALL_PROBE = STUDY / "data/versioned-collector/ebpf-high-syscall-v7-20261019/high_syscall_probe.sh"
PACKET_STRESS_PROBE = STUDY / "data/versioned-collector/loss-mitigation-smoke-20261019/loss_stress_probe.sh"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    cohort_rows = list(csv.DictReader(COHORT_CSV.open(newline="", encoding="utf-8")))
    smoke = read_json(FAMILY_SMOKE)
    lockbit_manifest = read_json(LOCKBIT_EXPERIMENT)
    lockbit_result = read_json(LOCKBIT_RESULTS)
    current_schema = "2026-10-19.8"
    current_runner_sha = "1f08c55ec6c2304cc4598971e9ba8e03fcbe0f31cb0d2ca39cf7bc21a18fbaa0"

    assert lockbit_manifest["runner"]["schema_version"] == current_schema
    assert lockbit_result["schema"] == current_schema
    assert lockbit_result["runner_sha256"] == current_runner_sha
    assert lockbit_result["quality"] == "accepted"
    assert lockbit_result["ebpf_lost_events"] == 0
    assert lockbit_result["packet_capture_statistics"]["dropped_by_kernel"] == 0
    assert sha256(RUNNER) == current_runner_sha

    malware_settings = smoke["malware"]
    family_order = [family for family in malware_settings["families"] if family.lower() != "unassigned"]
    assert len(family_order) == 28
    preferred = {row["family"]: row["artifact"] for row in malware_settings["samples"]}
    excluded = {malware_settings["exclude_artifact"]}
    by_family = {}
    for row in cohort_rows:
        family = row["group_id"].removeprefix("malware_signature::")
        if family.lower() == "unassigned":
            continue
        artifact = Path(row["sample_artifact"]).name
        if artifact in excluded:
            continue
        by_family.setdefault(family, []).append(row)

    host_samples = STUDY / "data/malware/full-cohort-323/samples"
    selected = []
    singleton_families = []
    for family in family_order:
        candidates = sorted(by_family.get(family, []), key=lambda row: row["sample_artifact"])
        if not candidates:
            raise ValueError(f"No eligible artifact for family {family}")
        if any(not (host_samples / row["sample_artifact"]).is_file() for row in candidates):
            raise ValueError(f"Cohort manifest has a missing host artifact for {family}")

        preferred_artifact = preferred.get(family)
        reused_artifact = lockbit_result["sample"] if family == "LockBit" else None
        anchor = reused_artifact or preferred_artifact
        anchor_row = next((row for row in candidates if row["sample_artifact"] == anchor), candidates[0])
        family_rows = [anchor_row]
        if len(candidates) >= 2:
            second = next(row for row in candidates if row["sample_artifact"] != anchor_row["sample_artifact"])
            family_rows.append(second)
        else:
            singleton_families.append(family)

        for index, row in enumerate(family_rows):
            artifact = row["sample_artifact"]
            reuse = family == "LockBit" and artifact == reused_artifact
            selected.append({
                "family": family,
                "artifact": artifact,
                "source_cohort": row["source_cohort"],
                "prior_sample_status": row["sample_status"],
                "selection_role": "prior_family_smoke_anchor" if artifact == preferred_artifact else
                                  "reused_validated_lockbit_v8" if reuse else "second_distinct_candidate",
                "execution": "reuse_existing_validated_run" if reuse else "collect_new_v8_run",
                "reused_run_root": "data/versioned-collector/lockbit-v8-recheck-20261019T151547Z"
                                     if reuse else None,
            })

    if len(selected) != 49 or len({row["artifact"] for row in selected}) != 49:
        raise ValueError(f"Expected 49 distinct malware artifacts, got {len(selected)}")
    if len(singleton_families) != 7:
        raise ValueError(f"Expected the approved seven singleton families, got {singleton_families}")
    new_malware = [row for row in selected if row["execution"] == "collect_new_v8_run"]
    reused = [row for row in selected if row["execution"] == "reuse_existing_validated_run"]
    if len(new_malware) != 48 or len(reused) != 1:
        raise ValueError(f"Unexpected malware capture/reuse count: {len(new_malware)}/{len(reused)}")

    manifests = ROOT / "manifests"
    manifests.mkdir(parents=True, exist_ok=True)
    (manifests / "malware-v8.txt").write_text(
        "\n".join(row["artifact"] for row in new_malware) + "\n", encoding="utf-8"
    )
    (manifests / "curl-controls.txt").write_text("curl-pair-01\ncurl-pair-02\n", encoding="utf-8")
    (manifests / "high-syscall.txt").write_text("high_syscall_probe.sh\n", encoding="utf-8")
    (manifests / "packet-stress.txt").write_text("loss_stress_probe.sh\n", encoding="utf-8")
    (ROOT / "family_selection.json").write_text(json.dumps({
        "named_families": family_order,
        "excluded_unassigned_bucket": True,
        "singleton_families": singleton_families,
        "distinct_malware_artifact_count": len(selected),
        "new_malware_capture_count": len(new_malware),
        "reused_current_v8_capture_count": len(reused),
        "samples": selected,
    }, indent=2) + "\n", encoding="utf-8")

    snapshots = {
        "malware": {
            "baseline": "clean-current-runner-2026-10-18.1-malware",
            "new": "clean-family-loss-v8-malware-2026-10-19",
            "guest_sample_directory": "/home/csci/Downloads/malware_full_cohort_323",
            "output": "runs/malware-v8",
            "manifest": "manifests/malware-v8.txt",
            "new_samples": len(new_malware),
            "reused_sample": reused[0],
        },
        "curl_controls": {
            "baseline": "clean-endpoint-2026-10-19.3-r2-benign",
            "new": "clean-family-loss-v8-curl-2026-10-19",
            "guest_sample_directory": "/home/csci/Downloads/tls-paired-20261019/benign",
            "guest_arguments_directory": "/home/csci/Downloads/tls-paired-20261019/arguments",
            "output": "runs/benign-curl-v8",
            "manifest": "manifests/curl-controls.txt",
            "samples": 2,
        },
        "high_syscall": {
            "baseline": "clean-ebpf-high-syscall-v8-2026-10-19",
            "new": "clean-family-loss-v8-high-syscall-2026-10-19",
            "guest_sample_directory": "/home/csci/Downloads/ebpf-high-syscall-probe",
            "output": "runs/benign-high-syscall-v8",
            "manifest": "manifests/high-syscall.txt",
            "probe_sha256": sha256(HIGH_SYSCALL_PROBE),
        },
        "packet_stress": {
            "baseline": "clean-loss-mitigation-2026-10-19-r2",
            "new": "clean-family-loss-v8-packet-stress-2026-10-19",
            "guest_sample_directory": "/home/csci/Downloads/loss-stress-probe",
            "output": "runs/benign-packet-stress-v8",
            "manifest": "manifests/packet-stress.txt",
            "probe_sha256": sha256(PACKET_STRESS_PROBE),
        },
    }
    manifest = {
        "run_id": ROOT.name,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Audit loss, drops, sensor availability, per-run telemetry counts, and archive retrieval across malware families and benign stress controls using the current runner.",
        "status": "frozen_before_staging",
        "selection_source": "data/malware/full-cohort-323/cohort_manifest.csv joined to runner-v4-family-smoke-20261019T130151Z/experiment_manifest.json",
        "selection_source_sha256": sha256(COHORT_CSV),
        "family_selection_source_sha256": sha256(FAMILY_SMOKE),
        "runner": {"schema_version": current_schema, "feature_count": 169, "sha256": current_runner_sha},
        "scripts": {"batch_sha256": sha256(BATCH), "staging_sha256": sha256(STAGING)},
        "prior_lockbit_reuse": {
            "manifest": "data/versioned-collector/lockbit-v8-recheck-20261019T151547Z/experiment_manifest.json",
            "results": "data/versioned-collector/lockbit-v8-recheck-20261019T151547Z/lockbit_v8_results.json",
            "run_directory": "data/versioned-collector/lockbit-v8-recheck-20261019T151547Z/runs/malware-v8/4dc06ecee904b9165fa699b026045c1b6408cc7061df3d2a7bc2b7b4f0879f4d.zip",
        },
        "malware_selection": {"named_family_count": 28, "distinct_artifacts": 49,
                              "new_captures": 48, "reused_validated_capture": 1,
                              "singleton_families": singleton_families},
        "benign_controls": {
            "count": 4,
            "samples": ["curl-pair-01", "curl-pair-02", "high_syscall_probe.sh", "loss_stress_probe.sh"],
            "purpose": ["low-volume TLS/network controls", "high syscall rate", "high packet rate plus syscalls"],
        },
        "vm": {
            "name": "Ubuntu-Clean-24.04", "sink_vm": "Sink", "network": "internal malnet only",
            "original_snapshot_to_restore": "clean-tls-paired-2026-10-19",
            "original_snapshot_uuid": "72de0a02-2e71-42b8-85e2-78c21d6b00f9",
            "snapshots": snapshots,
        },
        "settings": {
            "timeout_seconds": 8, "window_seconds": 0.5, "fixed_observation": True,
            "common_launch_wrapper": True, "ebpf": True, "interface": "enp0s3",
            "packet_capture_buffer_kb": 16384, "bpftrace_perf_rb_pages_per_cpu": 16384,
            "bpftrace_pages_source": "schema v8 default; no CLI override", "resume": False,
        },
        "acceptance": "For every run, compare run.json numeric packet/eBPF losses with collector logs; verify sensors active, quality status, schema/hash, raw and named event counts, 16-window finite feature rows, buffer restoration, retrieval status, and archive-to-host hashes. Preserve timeout/exit status separately from sensor quality.",
    }
    (ROOT / "experiment_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"family_count": len(family_order), "unique_malware_artifacts": len(selected),
                      "new_malware_captures": len(new_malware), "reused_lockbit_capture": len(reused),
                      "singleton_families": singleton_families, "benign_controls": 4}, indent=2))


if __name__ == "__main__":
    main()