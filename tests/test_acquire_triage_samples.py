import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from src.acquire_triage_samples import (
    candidate_status_for_reason,
    elf_architecture_bytes,
    has_family_signature,
    is_elf_bytes,
    load_existing,
    linux_report_files,
    normalize_architecture,
    safe_filename,
    search_url,
)


class TriageCandidateTests(unittest.TestCase):
    def test_family_signature_is_case_insensitive(self):
        report = {"signatures": [{"name": "Family: Qilin Ransomware"}]}
        self.assertTrue(has_family_signature(report, "qilin"))
        self.assertFalse(has_family_signature(report, "Akira"))

    def test_linux_report_files_excludes_non_linux_entries(self):
        report = {
            "files": [
                {"filename": "sample.elf", "tags": ["linux", "x64"]},
                {"filename": "sample.exe", "tags": ["windows", "x64"]},
            ]
        }
        self.assertEqual([item["filename"] for item in linux_report_files(report)], ["sample.elf"])

    def test_elf_magic_is_required(self):
        self.assertTrue(is_elf_bytes(b"\x7fELF" + b"payload"))
        self.assertFalse(is_elf_bytes(b"PK\x03\x04" + b"archive"))
        self.assertFalse(is_elf_bytes(b""))

    def test_elf_architecture_uses_machine_id_and_byte_order(self):
        x86_64 = bytearray(20)
        x86_64[:6] = b"\x7fELF\x02\x01"
        x86_64[18:20] = (62).to_bytes(2, "little")
        i386 = bytearray(20)
        i386[:6] = b"\x7fELF\x01\x01"
        i386[18:20] = (3).to_bytes(2, "little")
        sparc = bytearray(20)
        sparc[:6] = b"\x7fELF\x02\x02"
        sparc[18:20] = (2).to_bytes(2, "big")

        self.assertEqual(elf_architecture_bytes(bytes(x86_64)), "x86_64")
        self.assertEqual(elf_architecture_bytes(bytes(i386)), "i386")
        self.assertEqual(elf_architecture_bytes(bytes(sparc)), "SPARC")
        self.assertIsNone(elf_architecture_bytes(b"\x7fELF"))

    def test_architecture_aliases_normalize_to_elf_names(self):
        self.assertEqual(normalize_architecture("AMD64"), "x86_64")
        self.assertEqual(normalize_architecture("x86"), "i386")

    def test_runtime_architecture_failures_have_a_stable_status(self):
        self.assertEqual(
            candidate_status_for_reason("architecture mismatch: ARM (requires x86_64)"),
            "skipped_architecture_mismatch",
        )
        self.assertEqual(
            candidate_status_for_reason("sample size limit exceeded"),
            "skipped_size_limit",
        )

    def test_pruning_removes_only_non_matching_manifest_samples(self):
        def elf_sample(machine):
            data = bytearray(b"\x7fELF\x02\x01" + bytes(14))
            data[18:20] = machine.to_bytes(2, "little")
            return bytes(data)

        with tempfile.TemporaryDirectory() as temporary_dir:
            output_dir = Path(temporary_dir)
            native_path = output_dir / "native.elf"
            incompatible_path = output_dir / "i386.elf"
            native_path.write_bytes(elf_sample(62))
            incompatible_path.write_bytes(elf_sample(3))
            native_record = {
                "sample_id": "native-id",
                "stored_filename": native_path.name,
                "sha256": hashlib.sha256(native_path.read_bytes()).hexdigest(),
            }
            incompatible_record = {
                "sample_id": "i386-id",
                "stored_filename": incompatible_path.name,
                "sha256": hashlib.sha256(incompatible_path.read_bytes()).hexdigest(),
            }
            manifest_path = output_dir / "download_manifest.jsonl"
            manifest_path.write_text(
                "\n".join(json.dumps(record) for record in (native_record, incompatible_record)) + "\n",
                encoding="utf-8",
            )

            records, sample_ids, hashes, total_bytes, removed = load_existing(
                output_dir, manifest_path, "x86_64", prune_incompatible=True
            )

            self.assertEqual([record["sample_id"] for record in records], ["native-id"])
            self.assertEqual(sample_ids, {"native-id"})
            self.assertEqual(hashes, {native_record["sha256"]})
            self.assertEqual(total_bytes, native_path.stat().st_size)
            self.assertEqual([(record["sample_id"], arch) for record, arch, _ in removed], [("i386-id", "i386")])
            self.assertTrue(native_path.exists())
            self.assertFalse(incompatible_path.exists())
            retained = [json.loads(line) for line in manifest_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([record["sample_id"] for record in retained], ["native-id"])

    def test_search_url_uses_next_cursor_as_offset(self):
        cursor = "2026-10-15T12:25:54Z|261015-pkl46atxgx"
        parsed = urlparse(search_url("Mirai", 100, cursor))
        params = parse_qs(parsed.query)
        self.assertEqual(params["query"], ["family:Mirai tag:linux"])
        self.assertEqual(params["limit"], ["100"])
        self.assertEqual(params["offset"], [cursor])

    def test_filename_is_reduced_to_safe_basename(self):
        self.assertEqual(safe_filename("../../family name.elf"), "family_name.elf")


if __name__ == "__main__":
    unittest.main()