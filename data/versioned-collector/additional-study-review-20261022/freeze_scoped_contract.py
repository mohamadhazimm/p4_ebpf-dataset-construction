#!/usr/bin/env python3
"""Record explicit pilot approval and inspect executable regions without execution."""

import argparse
import hashlib
import json
import struct
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import audit_remediation as binary_audit
import propose_scoped_release as proposal_tools
from validate_remediation_workloads import digest, expect, save


ROOT = Path(__file__).resolve().parent
PROPOSAL = ROOT / "release-proposals/20261023T080357234937Z/proposal.json"
PROPOSAL_SHA256 = "7f78bb3b83f5bc0f9b14c281282bdb1bd572e2e19311e9e052de779212ec665e"


def executable_regions(content):
    expect(content[:4] == b"\x7fELF" and len(content) >= 64, "Missing ELF header")
    elf_class, encoding = content[4:6]
    expect(elf_class in (1, 2) and encoding in (1, 2), "Unsupported ELF encoding")
    endian = "<" if encoding == 1 else ">"
    header = struct.unpack_from(endian + ("HHIIIIIHHHHHH" if elf_class == 1 else "HHIQQQIHHHHHH"), content, 16)
    elf_type, machine = header[:2]
    program_offset, section_offset = header[4:6]
    program_size, program_count, section_size, section_count = header[8:12]
    expect(0 < program_count <= 256 and program_size >= (32 if elf_class == 1 else 56), "Unsupported program headers")
    expect(program_offset + program_size * program_count <= len(content), "Truncated program headers")
    segments, pieces = [], []
    for index in range(program_count):
        values = struct.unpack_from(endian + ("IIIIIIII" if elf_class == 1 else "IIQQQQQQ"), content, program_offset + index * program_size)
        kind = values[0]
        offset, size, flags = (values[1], values[4], values[6]) if elf_class == 1 else (values[2], values[5], values[1])
        expect(offset + size <= len(content), "Program region outside input: kind=%d offset=%d bytes=%d file_bytes=%d" % (kind, offset, size, len(content)))
        segments.append({"kind": kind, "flags": flags, "offset": offset, "size": size})
    if section_count:
        expect(section_count <= 65535 and section_size >= (40 if elf_class == 1 else 64), "Unsupported section headers")
        expect(section_offset > 0 and section_offset + section_size * section_count <= len(content), "Truncated section headers")
        for index in range(section_count):
            values = struct.unpack_from(endian + ("IIIIIIIIII" if elf_class == 1 else "IIQQQQIIQQ"), content, section_offset + index * section_size)
            kind, flags, offset, size = values[1], values[2], values[4], values[5]
            if flags & 4 and kind != 8 and size:
                expect(offset + size <= len(content), "Executable section outside input")
                pieces.append((offset, content[offset:offset + size]))
    representation = "executable_sections_without_names"
    if not pieces:
        representation = "executable_load_segments"
        pieces = [(row["offset"], content[row["offset"]:row["offset"] + row["size"]])
                  for row in segments if row["kind"] == 1 and row["flags"] & 1 and row["size"]]
    expect(bool(pieces), "No bounded executable regions")
    fingerprint = hashlib.sha256()
    regions = []
    for offset, piece in sorted(pieces):
        fingerprint.update(struct.pack("<Q", len(piece)))
        fingerprint.update(piece)
        regions.append({"offset": offset, "bytes": len(piece), "sha256": hashlib.sha256(piece).hexdigest()})
    return {"elf_class": elf_class, "machine": machine, "elf_type": elf_type,
            "strict_static": elf_type == 2 and not any(row["kind"] in (2, 3) for row in segments),
            "representation": representation, "code_sha256": fingerprint.hexdigest(),
            "code_bytes": sum(row["bytes"] for row in regions), "regions": regions}


def relationships(records):
    groups = defaultdict(list)
    for row in records:
        groups[(row["mode"], row["representation"], row["code_sha256"])].append(row)
    repeated = [rows for rows in groups.values() if len(rows) > 1]
    collisions = [[row["id"] for row in rows] for rows in repeated]
    crossing = [[row["id"] for row in rows] for rows in repeated if len({row["role"] for row in rows}) > 1]
    return {"exact_region_groups": collisions, "cross_role_exact_region_groups": crossing,
            "effective_roles_allowed": not crossing, "source_lineage_independence_certified": False}


def self_test():
    content = Path("/bin/true").read_bytes()
    facts = executable_regions(content)
    expect(facts["code_bytes"] > 0, "Actual ELF code missing")
    changed = bytearray(content)
    changed[facts["regions"][0]["offset"]] ^= 1
    expect(executable_regions(changed)["code_sha256"] != facts["code_sha256"], "Code mutation not detected")
    records = [{"id": "first", "role": "training", "mode": "native", **facts},
               {"id": "second", "role": "validation", "mode": "native", **facts}]
    expect(not relationships(records)["effective_roles_allowed"], "Cross-role code duplicate accepted")
    records[1]["role"] = "training"
    expect(relationships(records)["effective_roles_allowed"], "Same-role duplicate incorrectly crosses")
    for bad in (b"not ELF", content[:64]):
        try:
            executable_regions(bad)
        except ValueError:
            continue
        raise AssertionError("Truncated ELF accepted")
    return ["actual_code_mutation", "cross_role_duplicate", "same_role_group", "non_elf", "truncated_elf"]


def run():
    expect(digest(PROPOSAL) == PROPOSAL_SHA256, "Proposal changed after approval")
    proposal = json.loads(PROPOSAL.read_text())
    proposal_tools.validate(proposal["pairs"])
    for name, expected in proposal["input_hashes"].items():
        expect(digest(Path(name)) == expected, "Changed approved input: " + name)
    records, source_errors = [], []
    for pair in proposal["pairs"]:
        expect(digest(Path(pair["source"])) == pair["source_sha256"], "Changed source container")
        for label, path, expected in (("malware", pair["source"], pair["malware_sha256"]),
                                      ("benign", pair["benign_path"], pair["benign_sha256"])):
            content = binary_audit.read_binary(Path(path), expected)
            try:
                facts = executable_regions(content)
                expect(facts["strict_static"] and (facts["elf_class"], facts["machine"]) == ((1, 3) if pair["mode"] == proposal_tools.I386 else (2, 62)), "Selected mode differs")
            except ValueError as error:
                source_errors.append({"id": expected, "label": label, "unit": pair["unit"] if label == "benign" else pair["family"],
                                      "mode": pair["mode"], "role": pair["proposed_role"], "source": path, "error": str(error)})
                continue
            records.append({"id": expected, "label": label, "unit": pair["unit"] if label == "benign" else pair["family"],
                            "mode": pair["mode"], "role": pair["proposed_role"], "source": path, **facts})
    review = relationships(records)
    destination = ROOT / "release-contracts" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination.mkdir(parents=True, exist_ok=False)
    report = {"schema": "approved-scoped-engineering-contract-v1", "status": "approved_scope_pending_release_gates",
              "proposal": str(PROPOSAL), "proposal_sha256": PROPOSAL_SHA256,
              "approval": {"scope_choice": "Approve Engineering Pilot Scope", "performance_choice": "Approve These Prospective Limits",
                           "basis": "Explicit answers to Release Scope and Performance Limits in this session",
                           "malware_launch_authorized": False, "model_fitting_authorized": False, "old_capture_merge_authorized": False},
              "scope": proposal["proposed_scope"], "pairs": proposal["pairs"],
              "performance_limits": proposal["prospective_performance_acceptance_proposal"],
              "performance_limits_approved": True, "lineage_review": review, "binary_records": records,
              "source_errors": source_errors, "roles_effective": review["effective_roles_allowed"] and not source_errors, "collection_ready": False,
              "limitations": "Exact executable-region screening, not source/configuration lineage certification or proof that nonmatches are independent; no malware execution. Fail closed on cross-role duplicates; preserve every approved identity, do not substitute based on outcomes.",
              "negative_guards": self_test(), "input_hashes": {**proposal["input_hashes"], str(PROPOSAL): PROPOSAL_SHA256,
                                                                 str(Path(__file__).resolve()): digest(Path(__file__))}}
    report["performance_limits"]["failure_policy"] = "Preserve every failure; no automatic retries or post-result budget changes; acceptance only within the frozen benign envelope. Limits explicitly approved before measurement."
    if not report["roles_effective"]:
        report["status"] = "approved_scope_source_review_failed_preserved"
    save(destination / "contract.json", report)
    save(destination / "output_hashes.json", {"contract.json": digest(destination / "contract.json")})
    print(json.dumps({"contract": str(destination / "contract.json"), "sha256": digest(destination / "contract.json"),
                      "binary_records": len(records), "source_errors": source_errors, "lineage_review": review, "collection_ready": False}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args()
    print("PASS", self_test()) if options.self_test else run()