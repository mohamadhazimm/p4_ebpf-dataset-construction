#!/usr/bin/env python3
"""Review original training pools without executing workloads or changing captures."""

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import struct
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
ORIGINAL = ROOT.parent / "telemetry-2026-10-18.1-20261018T161354Z"
NATIVE = ROOT.parent / "cohort-100x100-v18-20261021/redesign-native-x64"
EXPANSION = ROOT.parent / "cohort-expansion-100x100-v18-20261021"
OLD_ORDER = NATIVE / "readiness/20261021T104951987641Z/case_order.csv"
NEW_ORDER = EXPANSION / "i386-heldout-amendment/20261021T201119747468Z/collection-readiness/20261021T203401085156Z/case_order.json"
COMBINED = EXPANSION / "combined-analysis/20261022T044439885696Z/analysis/eligible_dataset.csv"
BENIGN = STUDY / "data/benign/revision4/expanded/training"
PROJECT_ALIASES = {"zstd": "libzstd", "perl-base": "perl", "vim-tiny": "vim", "openssh-client": "openssh"}


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def identity(sample):
    match = re.fullmatch(r"([a-f0-9]{64})(?:\.(?:zip|triage))?", sample)
    if not match:
        raise ValueError("Not a hash-named malware identity: " + sample)
    return match[1]


def elf_header(prefix):
    if len(prefix) < 64 or prefix[:4] != b"\x7fELF":
        return {"mode": "not_elf_or_truncated"}
    elf_class, encoding = prefix[4:6]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        return {"mode": "unsupported_elf_encoding"}
    endian = "<" if encoding == 1 else ">"
    elf_type, machine = struct.unpack_from(endian + "HH", prefix, 16)
    if elf_class == 2:
        offset = struct.unpack_from(endian + "Q", prefix, 32)[0]
        entry_size, count = struct.unpack_from(endian + "HH", prefix, 54)
    else:
        offset = struct.unpack_from(endian + "I", prefix, 28)[0]
        entry_size, count = struct.unpack_from(endian + "HH", prefix, 42)
    if count == 65535 or entry_size < 4 or offset + entry_size * count > len(prefix):
        return {"mode": "program_headers_outside_bounded_prefix"}
    types = {struct.unpack_from(endian + "I", prefix, offset + entry_size * index)[0]
             for index in range(count)}
    linkage = "dynamic" if 3 in types else (
        "static-pie" if elf_type == 3 else "no_interpreter_dynamic_segment" if 2 in types else "static")
    architecture = {3: "i386", 62: "amd64", 40: "arm", 183: "arm64", 8: "mips"}.get(machine, str(machine))
    native = (machine, elf_class, encoding) in ((3, 1, 1), (62, 2, 1))
    return {"mode": f"{'native' if native else 'non_native'}_{architecture}_{linkage}",
            "elf_class": elf_class, "elf_type": elf_type, "machine": machine,
            "byte_order": encoding, "linkage": linkage}


def inspect_member(path, expected):
    process = subprocess.Popen(["7z", "x", "-so", "-pinfected", str(path)],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    checksum, prefix, size = hashlib.sha256(), bytearray(), 0
    try:
        while chunk := process.stdout.read(1024 * 1024):
            size += len(chunk)
            if size > 64 * 1024 * 1024:
                raise ValueError("member exceeds 64-MiB offline inspection bound")
            checksum.update(chunk)
            if len(prefix) < 1024 * 1024:
                prefix.extend(chunk[:1024 * 1024 - len(prefix)])
        if process.wait(timeout=30) != 0:
            raise ValueError("archive reader failed")
        if checksum.hexdigest() != expected:
            raise ValueError("streamed content hash differs from sample identity")
        return {**elf_header(prefix), "member_sha256": checksum.hexdigest(), "member_bytes": size}
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def old_run(cohort, sample):
    directory = ORIGINAL / "runs" / cohort / sample
    status = {}
    host = directory / "host_run.txt"
    if host.is_file():
        status = dict(line.split("=", 1) for line in host.read_text().splitlines() if "=" in line)
    chosen_path = directory / "chosen.txt"
    chosen = dict(line.split("=", 1) for line in chosen_path.read_text().splitlines() if "=" in line) if chosen_path.is_file() else {}
    matches = list(directory.glob("output/run_*/run.json"))
    if len(matches) > 1:
        raise ValueError("Ambiguous old run metadata: " + sample)
    metadata = json.loads(matches[0].read_text()) if matches else {}
    return {"old_retrieval_status": status.get("status", "partial" if directory.exists() else "not_started"),
            "old_metadata_available": bool(metadata),
            "old_metadata_path": str(matches[0].relative_to(STUDY)) if matches else "",
            "old_metadata_sha256": digest(matches[0]) if matches else "",
            "old_chosen_arch": chosen.get("sample_arch", ""),
            "old_chosen_elf_class": chosen.get("sample_elf_class", ""),
            "old_chosen_sha256": digest(chosen_path) if chosen_path.is_file() else "",
            "old_schema": metadata.get("telemetry_schema_version", ""),
            "old_process_status": metadata.get("status", ""),
            "old_return_code": metadata.get("return_code", ""),
            "old_artifact_type": metadata.get("sample_artifact_type", ""),
            "old_reported_pcap_kernel_drops": metadata.get("packet_capture_dropped_by_kernel", ""),
            "old_has_target_exec_evidence": "target_exec" in metadata,
            "old_has_current_quality_status": "collection_quality_status" in metadata}


def self_test():
    sample_hash = "a" * 64
    assert identity(sample_hash + ".zip") == identity(sample_hash + ".triage")
    for elf_class, machine in ((1, 3), (2, 62)):
        for elf_type, expected in ((2, "static"), (3, "static-pie")):
            header = bytearray(64)
            header[:6] = b"\x7fELF" + bytes((elf_class, 1))
            struct.pack_into("<HH", header, 16, elf_type, machine)
            struct.pack_into("<HH", header, 42 if elf_class == 1 else 54, 32, 0)
            assert elf_header(header)["linkage"] == expected
    assert elf_header(b"#!/bin/sh\n")["mode"] == "not_elf_or_truncated"
    assert PROJECT_ALIASES["zstd"] == "libzstd"
    print("PASS: extension-independent identity, x64/i386 static versus static-PIE, non-ELF rejection")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    frozen_path = ORIGINAL / "collection_manifest.json"
    frozen = json.loads(frozen_path.read_text())
    inputs = [Path(__file__), frozen_path, OLD_ORDER, NEW_ORDER, COMBINED,
              BENIGN / "workload_manifest.csv", BENIGN / "sample_list.txt"]
    manifests = {}
    for name, details in frozen["cohorts"].items():
        path = ORIGINAL / details["manifest"]
        if digest(path) != details["manifest_sha256"]:
            raise ValueError("Original frozen manifest changed: " + name)
        names = path.read_text().splitlines()
        if len(names) != details["expected_samples"] or len(set(names)) != len(names):
            raise ValueError("Original manifest count/uniqueness differs")
        manifests[name] = names
        inputs.append(path)
    if (BENIGN / "sample_list.txt").read_text().splitlines() != manifests["benign-training-500"]:
        raise ValueError("Current benign list differs from frozen list")
    old_order = read_csv(OLD_ORDER)
    new_order = json.loads(NEW_ORDER.read_text())
    prior = defaultdict(list)
    prior_families = set()
    for cohort, order in (("native_x64", old_order), ("native_expansion", new_order)):
        for row in order:
            if row.get("class", row.get("label")) == "malware":
                prior[identity(row["sample"])].append({"cohort": cohort, "split": row["split"], "group_id": row["group_id"]})
                prior_families.add(row["group_id"].removeprefix("malware_signature::").casefold())
    used_rows = read_csv(COMBINED)
    used_groups = {row["group_id"].removeprefix("malware_signature::").casefold()
                   for row in used_rows if row["class"] == "malware"}
    used_projects = {PROJECT_ALIASES.get(row["group_id"].removeprefix("benign_project::"), row["group_id"].removeprefix("benign_project::"))
                     for row in used_rows if row["class"] == "benign"}
    family_sources, archive_sources, label_details = defaultdict(list), defaultdict(list), defaultdict(list)
    historical_membership = {}
    for relative, key in (("data/malware/malware_sample_source_catalog.csv", "sha256"),
                          ("data/malware/catalog/archive_manifest.csv", "sample_sha256"),
                          ("data/malware/revision4/training521_holdout461_20261017/malware_hash_labels.csv", "sha256"),
                          ("data/malware/full-cohort-323/cohort_manifest.csv", "sample_artifact")):
        path = STUDY / relative
        inputs.append(path)
        for row in read_csv(path):
            sample_hash = identity(row[key])
            family = row.get("malware_family", row.get("family_label", "")).strip()
            if "telemetry_model_membership" in row:
                historical_membership[sample_hash] = row["telemetry_model_membership"]
            if family and not any(token in family.casefold() for token in ("unassigned", "unknown", "unclassified", "not supplied")):
                family_sources[sample_hash].append((family, relative))
                label_details[sample_hash].append({"family": family, "source": relative,
                    "confidence": row.get("family_confidence", row.get("classification_confidence", "")),
                    "basis": row.get("label_source", row.get("classification_basis", "")),
                    "attack_type": row.get("attack_type", row.get("malware_type", row.get("family_type", "")))})
            if "storage_path" in row:
                archive_sources[sample_hash].append((STUDY / row["storage_path"], row["archive_sha256"]))
            elif key == "sample_artifact":
                archive_sources[sample_hash].append((path.parent / "samples" / row[key], None))
    malware = []
    for index, sample in enumerate(manifests["malware-training-535"], start=1):
        sample_hash = identity(sample)
        families = sorted({family for family, _source in family_sources[sample_hash]})
        normalized = {family.casefold() for family in families}
        row = {"sample": sample, "sha256": sample_hash, "family_labels": ";".join(families),
             "family_evidence": label_details[sample_hash],
               "family_status": "known" if len(normalized) == 1 else "conflicting" if normalized else "unknown",
               "family_absent_from_combined": bool(normalized) and not normalized & used_groups,
               "family_absent_from_both_native_orders": bool(normalized) and not normalized & prior_families,
               "historical_model_membership": historical_membership.get(sample_hash, "unknown"),
               "prior_native_case": bool(prior[sample_hash]), "prior_native_roles": prior[sample_hash],
               "source_archive_path": "", "source_member_verified": False,
               "mode": "source_unavailable_or_uninspected", **old_run("malware-training-535", sample)}
        for archive, expected in archive_sources[sample_hash]:
            if not archive.is_file():
                continue
            archive_hash = digest(archive)
            if expected and archive_hash != expected:
                raise ValueError("Catalog archive hash differs: " + str(archive))
            row.update(source_archive_path=str(archive.relative_to(STUDY)), source_archive_sha256=archive_hash)
            try:
                row.update(inspect_member(archive, sample_hash), source_member_verified=True)
            except ValueError as error:
                row["source_review_error"] = str(error)
            break
        malware.append(row)
        if index % 100 == 0:
            print(f"REVIEWED {index}/535 malware manifest entries", flush=True)
    manifest_rows = read_csv(BENIGN / "workload_manifest.csv")
    by_sample = {row["sample_artifact"]: row for row in manifest_rows}
    if len(manifest_rows) != 500 or set(by_sample) != set(manifests["benign-training-500"]):
        raise ValueError("Benign identity manifest differs")
    benign = []
    for sample in manifests["benign-training-500"]:
        row = dict(by_sample[sample])
        path = BENIGN / "workload_scripts" / sample
        if digest(path) != row["sha256"]:
            raise ValueError("Benign script hash differs: " + sample)
        text = path.read_text()
        hosts = sorted({urlsplit(url).hostname for url in re.findall(r"https?://[^\s\"']+", text)})
        needs_review = []
        for host in hosts:
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = host == "localhost"
            if host != "10.0.0.1" and not loopback:
                needs_review.append(host)
        row.update(sample=sample, script_path=str(path.relative_to(STUDY)), shebang=text.startswith("#!"),
                   candidate_project=PROJECT_ALIASES.get(row["package"], row["package"]),
                   project_seen_in_combined=PROJECT_ALIASES.get(row["package"], row["package"]) in used_projects,
                   declared_url_hosts=hosts, hosts_need_isolated_endpoint_review=needs_review,
                   exact_script_seen_in_native_cohort=any(item["sample"] == sample for item in old_order + new_order),
                   **old_run("benign-training-500", sample))
        benign.append(row)
    normalized_families = Counter(row["family_labels"].split(";")[0].casefold() for row in malware if row["family_status"] == "known")
    additional_families = Counter(row["family_labels"].split(";")[0].casefold() for row in malware
                                  if row["family_status"] == "known" and not row["prior_native_case"])
    report = {
        "status": "offline_inventory_and_design_review_only", "created_utc": datetime.now(timezone.utc).isoformat(),
        "collection_ready": False, "collection_started": False, "sample_executions": 0, "model_fits": 0,
        "original_root": str(ORIGINAL.relative_to(STUDY)), "old_schema": frozen["telemetry_schema_version"],
        "old_runner_sha256": frozen["malware_runner_sha256"],
        "original_counts": {name: len(names) for name, names in manifests.items()},
        "original_training_vs_holdout_identity_overlap": sorted({identity(name) for name in manifests["malware-training-535"]}
            & {identity(name) for name in manifests["malware-holdout-323"]}),
        "malware_summary": {"entries": len(malware), "unique_identities": len({row["sha256"] for row in malware}),
            "retrieval_status": dict(Counter(row["old_retrieval_status"] for row in malware)),
            "metadata_records": sum(row["old_metadata_available"] for row in malware),
            "family_metadata_status": dict(Counter(row["family_status"] for row in malware)),
            "family_counts": dict(Counter(row["family_labels"] or "unknown" for row in malware)),
            "case_normalized_family_counts": dict(normalized_families),
            "case_normalized_family_groups": len(normalized_families),
            "mirai_plus_xorddos": normalized_families["mirai"] + normalized_families["xorddos"],
            "historical_model_membership_counts": dict(Counter(row["historical_model_membership"] for row in malware)),
            "prior_native_case_overlap": sum(row["prior_native_case"] for row in malware),
            "not_in_prior_native_orders": sum(not row["prior_native_case"] for row in malware),
            "available_member_verified_sources": sum(row["source_member_verified"] for row in malware),
            "verified_mode_counts": dict(Counter(row["mode"] for row in malware)),
            "known_family_not_in_combined": sorted({row["family_labels"] for row in malware
                if row["family_status"] == "known" and row["family_absent_from_combined"]}),
            "known_family_not_in_both_native_orders": sorted({row["family_labels"] for row in malware
                if row["family_status"] == "known" and row["family_absent_from_both_native_orders"]}),
            "additional_identity_family_counts": dict(additional_families),
            "illustrative_family_cap_totals_before_mode_or_quality_selection": {
                str(cap): sum(min(count, cap) for count in additional_families.values()) for cap in (5, 10, 20)},
            "saved_chosen_arch_counts": dict(Counter(row["old_chosen_arch"] or "unavailable" for row in malware)),
            "old_process_status_counts": dict(Counter(row["old_process_status"] or "unavailable" for row in malware)),
            "old_pcap_drop_positive_records": sum(isinstance(row["old_reported_pcap_kernel_drops"], (int, float))
                and row["old_reported_pcap_kernel_drops"] > 0 for row in malware)},
        "benign_summary": {"entries": len(benign), "distinct_script_hashes": len({row["sha256"] for row in benign}),
            "all_shebang_scripts": all(row["shebang"] for row in benign),
            "package_counts": dict(Counter(row["package"] for row in benign)),
            "declared_package_template_pairs": len({(row["package"], row["template_artifact"]) for row in benign}),
            "template_counts_by_package": {package: len({row["template_artifact"] for row in benign if row["package"] == package})
                for package in sorted({row["package"] for row in benign})},
            "retrieval_status": dict(Counter(row["old_retrieval_status"] for row in benign)),
            "declared_controlled_download_profiles": sum(row["controlled_sink_download"].lower() == "true" for row in benign),
            "scripts_with_url_hosts_requiring_review": sum(bool(row["hosts_need_isolated_endpoint_review"]) for row in benign),
            "project_labels_absent_from_combined": sorted({row["candidate_project"] for row in benign if not row["project_seen_in_combined"]}),
            "project_aliases_applied": PROJECT_ALIASES},
        "input_hashes": {str(path.relative_to(STUDY)): digest(path) for path in inputs},
        "limitations": [
            "Catalog metadata coverage is not a complete family inventory of the 535 sources.",
            "Not in the two native case orders does not mean historically untouched; original training captures were already collected.",
            "Original retrieval completion is not current quality acceptance, target activation or network attribution.",
            "Old runner telemetry cannot be merged with .18 without explicit semantic compatibility analysis.",
            "Case normalization only merges spelling case; broader family taxonomy and label confidence still require review.",
            "Package names are not independently verified upstream project identities; template counts are declared manifest pairs.",
            "URL scanning is a conservative lexical review, not a shell parser or proof of actual public-network communication.",
            "This review neither reauthenticates benign package builds nor certifies any new workload safe or ready.",
        ],
    }
    attempt = ROOT / "attempts" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    for name, rows in (("malware-535-review.json", malware), ("benign-500-review.json", benign), ("summary.json", report)):
        (attempt / name).write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"attempt": str(attempt), **{name: value for name, value in report.items()
                     if name not in ("input_hashes", "limitations")}}, indent=2), flush=True)


if __name__ == "__main__":
    main()