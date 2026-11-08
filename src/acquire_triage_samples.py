#!/usr/bin/env python3
"""Collect Triage Linux ELF samples into a restricted local directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from typing import Any


API_BASE = "https://api.tria.ge/v0"
DEFAULT_OUTPUT = Path("data/malware/revision4/triage-incoming")
DEFAULT_TARGET_TOTAL = 108
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 200
DEFAULT_PAGES_PER_FAMILY = 2
DEFAULT_REQUIRED_ARCH = "x86_64"
ARCHITECTURE_NAMES = {
    2: "SPARC",
    3: "i386",
    4: "M68K",
    8: "MIPS",
    20: "PPC",
    21: "PPC64",
    22: "S390",
    40: "ARM",
    42: "SuperH",
    62: "x86_64",
    93: "EM_93",
    183: "AArch64",
    243: "RISC-V",
}
ARCHITECTURE_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86_64": "x86_64",
    "i386": "i386",
    "i486": "i386",
    "i586": "i386",
    "i686": "i386",
    "x86": "i386",
}
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
FAMILY_SPECS = (
    ("botnet_ddos", "Mirai"),
    ("ddos", "XorDDoS"),
    ("ransomware", "Akira"),
    ("ransomware", "Qilin"),
    ("ransomware", "LockBit"),
    ("ransomware", "PromptLock"),
    ("backdoor", "BrickStorm"),
    ("backdoor", "DeskRAT"),
)


class TriageRequestError(RuntimeError):
    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(message)
        self.status = status


def api_auth_key() -> str:
    value = os.environ.get("TRIAGE_API_KEY", "").strip()
    if value:
        return value
    for parent in Path(__file__).resolve().parents:
        env_path = parent / ".env"
        if not env_path.is_file():
            continue
        try:
            lines = env_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            name, separator, value = line.partition("=")
            if not separator or name.strip() != "TRIAGE_API_KEY":
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                return value[1:-1].strip()
            return value.split(" #", 1)[0].strip()
    return ""


def search_url(family: str, page_size: int, offset: str | None = None) -> str:
    params = {"query": f"family:{family} tag:linux", "limit": str(page_size)}
    if offset:
        params["offset"] = offset
    return f"{API_BASE}/search?{urlencode(params)}"


def _curl_config(api_key: str, url: str) -> str:
    if not api_key or "\n" in api_key or "\r" in api_key:
        raise ValueError("TRIAGE_API_KEY is missing or malformed")
    escaped_key = api_key.replace("\\", "\\\\").replace('"', '\\"')
    escaped_url = url.replace("\\", "\\\\").replace('"', '\\"')
    return (
        f'header = "Authorization: Bearer {escaped_key}"\n'
        'header = "Accept: application/json"\n'
        f'url = "{escaped_url}"\n'
    )


def curl_request(
    url: str,
    api_key: str,
    timeout: int,
    max_bytes: int,
    output_path: Path | None = None,
) -> bytes | int:
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        str(timeout),
        "--write-out",
        "%{http_code}",
        "--config",
        "-",
    ]
    if output_path is not None:
        command.extend(
            ["--max-filesize", str(max_bytes), "--output", str(output_path)]
        )
    try:
        result = subprocess.run(
            command,
            input=_curl_config(api_key, url).encode("utf-8"),
            capture_output=True,
            timeout=timeout + 5,
        )
    except FileNotFoundError as error:
        raise RuntimeError("curl is required for Triage API access") from error
    except subprocess.TimeoutExpired as error:
        raise TriageRequestError(None, "Triage request timed out") from error
    status_text = result.stdout[-3:].decode("ascii", "ignore")
    status = int(status_text) if status_text.isdigit() else None
    if result.returncode or status != 200:
        message = f"Triage request failed with HTTP {status or 'unknown'}"
        if result.returncode:
            message += f" (curl exit {result.returncode})"
        raise TriageRequestError(status, message)
    if output_path is not None:
        size = output_path.stat().st_size if output_path.exists() else 0
        if size > max_bytes:
            raise ValueError("Triage sample exceeded the configured size limit")
        return size
    body = result.stdout[:-3]
    if len(body) > max_bytes:
        raise ValueError("Triage response exceeded the configured size limit")
    return body


def api_json(
    url: str,
    api_key: str,
    max_bytes: int = 32 * 1024 * 1024,
    timeout: int = 30,
) -> dict[str, Any]:
    body = curl_request(url, api_key, timeout=timeout, max_bytes=max_bytes)
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError("Triage returned invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("Triage returned an unexpected JSON object")
    return value


def search_family(
    family: str,
    api_key: str,
    page_size: int,
    pages: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    offset: str | None = None
    seen_offsets: set[str] = set()
    for _ in range(pages):
        payload = api_json(search_url(family, page_size, offset), api_key)
        data = payload.get("data", [])
        if not isinstance(data, list):
            raise ValueError("Triage search did not return a data list")
        rows.extend(row for row in data if isinstance(row, dict))
        next_offset = payload.get("next")
        if not isinstance(next_offset, str) or not next_offset:
            break
        if next_offset in seen_offsets or next_offset == offset:
            raise ValueError("Triage pagination cursor did not advance")
        seen_offsets.add(next_offset)
        offset = next_offset
    return rows


def has_family_signature(report: dict[str, Any], family: str) -> bool:
    signatures = report.get("signatures", [])
    if not isinstance(signatures, list):
        return False
    labels = " ".join(
        " ".join(
            str(signature.get(field, ""))
            for field in ("name", "description", "family")
        )
        for signature in signatures
        if isinstance(signature, dict)
    )
    return family.casefold() in labels.casefold()


def linux_report_files(report: dict[str, Any]) -> list[dict[str, Any]]:
    files = report.get("files", [])
    if not isinstance(files, list):
        return []
    return [
        item
        for item in files
        if isinstance(item, dict)
        and "linux"
        in {str(tag).casefold() for tag in item.get("tags", [])}
    ]


def is_elf_bytes(data: bytes) -> bool:
    return data.startswith(b"\x7fELF")


def is_elf_file(path: Path) -> bool:
    with path.open("rb") as sample:
        return is_elf_bytes(sample.read(4))


def elf_architecture_bytes(data: bytes) -> str | None:
    if len(data) < 20 or not is_elf_bytes(data):
        return None
    if data[4] not in {1, 2} or data[5] not in {1, 2}:
        return None
    byte_order = "little" if data[5] == 1 else "big"
    machine = int.from_bytes(data[18:20], byte_order)
    return ARCHITECTURE_NAMES.get(machine, f"EM_{machine}")


def elf_architecture(path: Path) -> str | None:
    with path.open("rb") as sample:
        return elf_architecture_bytes(sample.read(20))


def normalize_architecture(value: str) -> str:
    normalized = value.strip().casefold().replace("-", "_")
    normalized = ARCHITECTURE_ALIASES.get(normalized, normalized)
    known_architectures = set(ARCHITECTURE_NAMES.values())
    for architecture in known_architectures:
        if architecture.casefold().replace("-", "_") == normalized:
            return architecture
    raise ValueError(f"Unsupported architecture name: {value}")


def safe_filename(filename: str) -> str:
    basename = Path(filename).name
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", basename).strip("._")[:100]
    return safe or "sample"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_existing(
    output_dir: Path,
    manifest_path: Path,
    required_arch: str,
    prune_incompatible: bool = False,
) -> tuple[
    list[dict[str, Any]],
    set[str],
    set[str],
    int,
    list[tuple[dict[str, Any], str, Path]],
]:
    records: list[dict[str, Any]] = []
    sample_ids: set[str] = set()
    hashes: set[str] = set()
    total_bytes = 0
    manifest_records: list[dict[str, Any]] = []
    incompatible_records: list[tuple[dict[str, Any], str, Path]] = []
    if not manifest_path.exists():
        return records, sample_ids, hashes, total_bytes, incompatible_records
    with manifest_path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid JSONL at {manifest_path}:{line_number}") from error
            stored_name = record.get("stored_filename")
            if not isinstance(stored_name, str) or Path(stored_name).name != stored_name:
                raise ValueError(f"Unsafe stored filename at {manifest_path}:{line_number}")
            sample_path = output_dir / stored_name
            if not sample_path.is_file():
                manifest_records.append(record)
                continue
            digest = sha256_file(sample_path)
            if digest != record.get("sha256") or not is_elf_file(sample_path):
                raise ValueError(f"Existing sample failed integrity checks: {stored_name}")
            architecture = elf_architecture(sample_path)
            if architecture != required_arch:
                incompatible_records.append((record, architecture or "unknown", sample_path))
                if not prune_incompatible:
                    manifest_records.append(record)
                continue
            manifest_records.append(record)
            records.append(record)
            sample_id = record.get("sample_id")
            if isinstance(sample_id, str):
                sample_ids.add(sample_id)
            hashes.add(digest)
            total_bytes += sample_path.stat().st_size
    if prune_incompatible and incompatible_records:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=manifest_path.parent,
            prefix=f".{manifest_path.name}.", delete=False,
        ) as temporary:
            replacement_path = Path(temporary.name)
            os.chmod(replacement_path, 0o600)
            for record in manifest_records:
                temporary.write(json.dumps(record, sort_keys=True) + "\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(replacement_path, manifest_path)
        for _, _, sample_path in incompatible_records:
            sample_path.unlink(missing_ok=True)
    return records, sample_ids, hashes, total_bytes, incompatible_records


def append_manifest(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as manifest:
        os.chmod(path, 0o600)
        manifest.write(json.dumps(record, sort_keys=True) + "\n")
        manifest.flush()
        os.fsync(manifest.fileno())


def append_candidate_status(
    path: Path,
    *,
    status: str,
    family: str,
    category: str,
    required_arch: str,
    sample_id: str | None = None,
    digest: str | None = None,
    actual_arch: str | None = None,
    stored_filename: str | None = None,
    reason: str | None = None,
) -> None:
    record = {
        "status": status,
        "reason": reason,
        "sample_id": sample_id,
        "sha256": digest,
        "family": family,
        "selection_category": category,
        "required_arch": required_arch,
        "actual_arch": actual_arch,
        "stored_filename": stored_filename,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    with path.open("a", encoding="utf-8") as destination:
        os.chmod(path, 0o600)
        destination.write(json.dumps(record, sort_keys=True) + "\n")
        destination.flush()
        os.fsync(destination.fileno())


def candidate_status_for_reason(reason: str) -> str:
    if reason == "family signature mismatch":
        return "skipped_family_signature_mismatch"
    if reason == "static report has no Linux-tagged file":
        return "skipped_no_linux_file"
    if reason == "downloaded original is not ELF":
        return "skipped_not_elf"
    if reason.startswith("architecture mismatch:"):
        return "skipped_architecture_mismatch"
    if "timed out" in reason:
        return "skipped_timeout"
    if "unavailable" in reason:
        return "skipped_unavailable"
    if "size limit" in reason:
        return "skipped_size_limit"
    return "skipped_candidate"


def make_record(
    sample_id: str,
    family: str,
    category: str,
    original_name: str,
    destination: Path,
    digest: str,
    size: int,
    linux_files: list[dict[str, Any]],
    report: dict[str, Any],
) -> dict[str, Any]:
    signatures = report.get("signatures", [])
    signature_names = [
        str(item.get("name") or item.get("description") or "")
        for item in signatures
        if isinstance(item, dict)
    ] if isinstance(signatures, list) else []
    report_files = [
        {field: item[field] for field in ("filename", "filesize", "sha256", "tags") if field in item}
        for item in linux_files
    ]
    return {
        "source": "Triage",
        "sample_id": sample_id,
        "family": family,
        "selection_category": category,
        "original_filename": original_name,
        "stored_filename": destination.name,
        "sha256": digest,
        "architecture": elf_architecture(destination),
        "size_bytes": size,
        "static_linux_files": report_files,
        "signatures": signature_names,
        "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
        "extracted": False,
        "executed": False,
    }


def download_candidate(
    row: dict[str, Any],
    family: str,
    category: str,
    api_key: str,
    output_dir: Path,
    manifest_path: Path,
    max_sample_bytes: int,
    remaining_bytes: int,
    required_arch: str,
) -> tuple[dict[str, Any] | None, str | None]:
    sample_id = row.get("id")
    digest = str(row.get("sha256", "")).lower()
    if not isinstance(sample_id, str) or not HASH_PATTERN.fullmatch(digest):
        return None, "search result lacked a valid sample ID or SHA-256"
    try:
        report = api_json(
            f"{API_BASE}/samples/{sample_id}/reports/static", api_key, timeout=20
        )
    except TriageRequestError as error:
        if error.status in {403, 404} or error.status is None:
            reason = "static report timed out" if error.status is None else "static report unavailable"
            return None, reason
        raise
    if not has_family_signature(report, family):
        return None, "family signature mismatch"
    linux_files = linux_report_files(report)
    if not linux_files:
        return None, "static report has no Linux-tagged file"
    original_name = str(row.get("filename") or "sample")
    destination = output_dir / f"{family.lower()}-{sample_id}-{safe_filename(original_name)}"
    if destination.exists():
        actual = sha256_file(destination)
        if actual != digest or not is_elf_file(destination):
            raise ValueError(f"Refusing to overwrite existing file: {destination.name}")
        actual_arch = elf_architecture(destination)
        if actual_arch != required_arch:
            return None, f"architecture mismatch: {actual_arch or 'unknown'} (requires {required_arch})"
        size = destination.stat().st_size
        record = make_record(
            sample_id, family, category, original_name, destination, digest, size, linux_files, report
        )
        append_manifest(manifest_path, record)
        return record, None
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=output_dir, prefix=".download-", delete=False) as temporary:
            temp_path = Path(temporary.name)
        os.chmod(temp_path, 0o600)
        size_limit = min(max_sample_bytes, remaining_bytes)
        if size_limit < 1:
            return None, "total size limit reached"
        try:
            curl_request(
                f"{API_BASE}/samples/{sample_id}/sample",
                api_key,
                timeout=120,
                max_bytes=size_limit,
                output_path=temp_path,
            )
        except TriageRequestError as error:
            if error.status in {403, 404} or error.status is None:
                reason = "sample download timed out" if error.status is None else "sample download unavailable"
                return None, reason
            if "size limit" in str(error).casefold():
                return None, "sample size limit exceeded"
            raise
        except ValueError as error:
            if "size limit" in str(error).casefold():
                return None, "sample size limit exceeded"
            raise
        size = temp_path.stat().st_size
        if size > remaining_bytes:
            return None, "total size limit reached"
        if not is_elf_file(temp_path):
            return None, "downloaded original is not ELF"
        actual_arch = elf_architecture(temp_path)
        if actual_arch != required_arch:
            return None, f"architecture mismatch: {actual_arch or 'unknown'} (requires {required_arch})"
        actual = sha256_file(temp_path)
        if actual != digest:
            raise ValueError(f"Triage SHA-256 mismatch for {sample_id}; refusing to keep file")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, destination)
        record = make_record(
            sample_id, family, category, original_name, destination, actual, size, linux_files, report
        )
        append_manifest(manifest_path, record)
        return record, None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--family",
        action="append",
        metavar="CATEGORY:NAME",
        help="Override the default family list; 'CATEGORY:NAME' or 'NAME' (category defaults to 'linux'); repeatable",
    )
    parser.add_argument(
        "--target-total",
        type=int,
        default=DEFAULT_TARGET_TOTAL,
        help="Desired verified sample count matching --required-arch (default: 108)",
    )
    parser.add_argument(
        "--required-arch",
        default=DEFAULT_REQUIRED_ARCH,
        help="Required ELF architecture (default: x86_64)",
    )
    parser.add_argument(
        "--prune-incompatible",
        action="store_true",
        help="Delete manifest-linked samples that do not match --required-arch",
    )
    parser.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE)
    parser.add_argument("--pages-per-family", type=int, default=DEFAULT_PAGES_PER_FAMILY)
    parser.add_argument("--max-sample-mb", type=int, default=100)
    parser.add_argument("--max-total-gb", type=float, default=10.0)
    parser.add_argument("--plan-only", action="store_true", help="Search families but do not download")
    args = parser.parse_args(argv)
    if args.target_total < 1 or args.pages_per_family < 1:
        parser.error("target-total and pages-per-family must be positive")
    if not 1 <= args.page_size <= MAX_PAGE_SIZE:
        parser.error(f"page-size must be between 1 and {MAX_PAGE_SIZE}")
    if args.max_sample_mb < 1 or args.max_total_gb <= 0:
        parser.error("sample and total size limits must be positive")
    try:
        required_arch = normalize_architecture(args.required_arch)
    except ValueError as error:
        parser.error(str(error))
    if args.family:
        family_specs = tuple(
            tuple(spec.split(":", 1)) if ":" in spec else ("linux", spec)
            for spec in args.family
        )
    else:
        family_specs = FAMILY_SPECS
    if not shutil.which("curl"):
        print("curl is required for Triage API access", file=sys.stderr)
        return 2
    api_key = api_auth_key()
    if not api_key:
        print("Set TRIAGE_API_KEY in the environment or a parent .env file.", file=sys.stderr)
        return 2
    args.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(args.output_dir, 0o700)
    manifest_path = args.output_dir / "download_manifest.jsonl"
    status_path = args.output_dir / "candidate_status.jsonl"
    try:
        records, known_ids, known_hashes, total_bytes, incompatible_records = load_existing(
            args.output_dir,
            manifest_path,
            required_arch,
            prune_incompatible=args.prune_incompatible,
        )
        for record, actual_arch, sample_path in incompatible_records:
            sample_id = record.get("sample_id")
            digest = record.get("sha256")
            append_candidate_status(
                status_path,
                status=(
                    "removed_incompatible_architecture"
                    if args.prune_incompatible
                    else "skipped_existing_architecture_mismatch"
                ),
                family=str(record.get("family", "")),
                category=str(record.get("selection_category", "")),
                required_arch=required_arch,
                sample_id=sample_id if isinstance(sample_id, str) else None,
                digest=digest if isinstance(digest, str) else None,
                actual_arch=actual_arch,
                stored_filename=sample_path.name,
                reason=f"requires {required_arch}; found {actual_arch}",
            )
            if isinstance(sample_id, str):
                known_ids.add(sample_id)
            if isinstance(digest, str):
                known_hashes.add(digest)
        if incompatible_records and args.prune_incompatible:
            print(
                f"Removed {len(incompatible_records)} existing samples not matching "
                f"{required_arch}; audit written to {status_path}.",
                flush=True,
            )
        if len(records) >= args.target_total:
            print(
                f"Already have {len(records)} verified {required_arch} samples "
                f"in {args.output_dir}."
            )
            return 0
        pools: list[tuple[str, str, list[dict[str, Any]]]] = []
        for category, family in family_specs:
            print(f"Searching {family} ({category})...", flush=True)
            try:
                rows = search_family(family, api_key, args.page_size, args.pages_per_family)
            except TriageRequestError as error:
                # Transient server/rate errors (5xx, 429, timeouts) are non-fatal during search so one
                # family's hiccup does not discard the whole run; that family is simply skipped this pass.
                print(f"  search unavailable: {error}", file=sys.stderr)
                rows = []
            pools.append((category, family, rows))
            print(f"  candidates: {len(rows)}", flush=True)
        if args.plan_only:
            total_candidates = sum(len(rows) for _, _, rows in pools)
            print(f"Plan only: {total_candidates} search results across {len(pools)} family filters.")
            return 0
        total_limit = int(args.max_total_gb * 1024 * 1024 * 1024)
        max_sample_bytes = args.max_sample_mb * 1024 * 1024
        cursors = [0] * len(pools)
        seen_ids = set(known_ids)
        seen_hashes = set(known_hashes)
        total_count = len(records)
        new_count = 0
        consecutive_timeouts = 0
        skips: dict[str, int] = {}
        while total_count < args.target_total and total_bytes < total_limit:
            made_progress = False
            for index, (category, family, rows) in enumerate(pools):
                while cursors[index] < len(rows):
                    row = rows[cursors[index]]
                    cursors[index] += 1
                    sample_id = row.get("id")
                    digest = str(row.get("sha256", "")).lower()
                    if not isinstance(sample_id, str) or not HASH_PATTERN.fullmatch(digest):
                        skips["invalid search result"] = skips.get("invalid search result", 0) + 1
                        append_candidate_status(
                            status_path,
                            status="skipped_invalid_search_result",
                            family=family,
                            category=category,
                            required_arch=required_arch,
                            sample_id=sample_id if isinstance(sample_id, str) else None,
                            digest=digest if HASH_PATTERN.fullmatch(digest) else None,
                            reason="search result lacked a valid sample ID or SHA-256",
                        )
                        continue
                    if sample_id in seen_ids or digest in seen_hashes:
                        append_candidate_status(
                            status_path,
                            status="skipped_duplicate",
                            family=family,
                            category=category,
                            required_arch=required_arch,
                            sample_id=sample_id,
                            digest=digest,
                            reason="sample ID or SHA-256 was already seen",
                        )
                        continue
                    seen_ids.add(sample_id)
                    seen_hashes.add(digest)
                    made_progress = True
                    try:
                        record, reason = download_candidate(
                            row,
                            family,
                            category,
                            api_key,
                            args.output_dir,
                            manifest_path,
                            max_sample_bytes,
                            total_limit - total_bytes,
                            required_arch,
                        )
                    except TriageRequestError as error:
                        if error.status == 429 or error.status is None or (error.status and error.status >= 500):
                            append_candidate_status(
                                status_path,
                                status="retryable_api_error",
                                family=family,
                                category=category,
                                required_arch=required_arch,
                                sample_id=sample_id,
                                digest=digest,
                                reason=str(error),
                            )
                            raise
                        reason = str(error)
                        record = None
                    if record:
                        append_candidate_status(
                            status_path,
                            status="downloaded",
                            family=family,
                            category=category,
                            required_arch=required_arch,
                            sample_id=record["sample_id"],
                            digest=record["sha256"],
                            actual_arch=record.get("architecture"),
                            stored_filename=record["stored_filename"],
                        )
                        consecutive_timeouts = 0
                        total_count += 1
                        new_count += 1
                        total_bytes += int(record["size_bytes"])
                        print(
                            f"[{total_count}/{args.target_total}] {record['family']} "
                            f"{record['sample_id']} ({record['size_bytes']} bytes)",
                            flush=True,
                        )
                    elif reason:
                        append_candidate_status(
                            status_path,
                            status=candidate_status_for_reason(reason),
                            family=family,
                            category=category,
                            required_arch=required_arch,
                            sample_id=sample_id,
                            digest=digest,
                            actual_arch=(
                                reason.split(":", 1)[1].split("(", 1)[0].strip()
                                if reason.startswith("architecture mismatch:")
                                else None
                            ),
                            reason=reason,
                        )
                        skips[reason] = skips.get(reason, 0) + 1
                        print(f"  skipped {family} {sample_id}: {reason}", flush=True)
                        if reason.endswith("timed out"):
                            consecutive_timeouts += 1
                            if consecutive_timeouts >= 3:
                                raise RuntimeError(
                                    "Triage timed out on three consecutive candidates; "
                                    "verified samples are preserved for resume"
                                )
                        else:
                            consecutive_timeouts = 0
                    break
                if total_count >= args.target_total or total_bytes >= total_limit:
                    break
            if not made_progress:
                break
        print(
            f"Verified {new_count} new {required_arch} samples; {total_count} total; "
            f"{total_bytes} bytes in {args.output_dir}.",
            flush=True,
        )
        if skips:
            print("Skipped candidates: " + ", ".join(f"{key}={value}" for key, value in sorted(skips.items())))
        if total_count < args.target_total:
            print("Target not reached; rerun to resume or broaden the family filters.", file=sys.stderr)
            return 1
        print("Samples remain unextracted, non-executable, and were not run.")
        return 0
    except KeyboardInterrupt:
        print("Interrupted; verified samples are preserved. Rerun to resume.", file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())