import csv
import tempfile
import unittest
from pathlib import Path

from scripts.build_grouped_capture_dataset import (
    audit_openat_events,
    build_feature_row,
    load_sample,
    select_feature_fields,
)
from src.build_dataset import load_telemetry


class BuildDatasetPackageGroupTests(unittest.TestCase):
    def test_noncompleted_run_is_excluded_without_opening_output(self):
        with tempfile.TemporaryDirectory() as directory:
            runs_root = Path(directory)
            sample_dir = runs_root / "failed.zip"
            sample_dir.mkdir()
            (sample_dir / "host_run.txt").write_text("status=runner_failed\n")

            result = load_sample(
                "failed.zip",
                {"label": "1"},
                runs_root,
                "expected-hash",
                None,
            )

        self.assertEqual(result, (None, "runner_failed", None, None))

    def test_openat_audit_counts_path_payloads_and_successes(self):
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "ebpf_events.csv"
            with event_path.open("w", newline="", encoding="utf-8") as destination:
                writer = csv.DictWriter(destination, fieldnames=["event", "detail"])
                writer.writeheader()
                writer.writerows(
                    [
                        {"event": "openat", "detail": "path=/etc/ld.so.cache flags=524288"},
                        {"event": "openat", "detail": "path= flags=524288"},
                        {"event": "openat_success", "detail": "fd=3"},
                        {"event": "openat2", "detail": "path=/tmp/file flags=0"},
                    ]
                )

            counts = audit_openat_events(event_path)

        self.assertEqual(counts["raw_openat"], 2)
        self.assertEqual(counts["openat_with_path_field"], 2)
        self.assertEqual(counts["openat_nonempty_path"], 1)
        self.assertEqual(counts["openat_success"], 1)
        self.assertEqual(counts["raw_openat2"], 1)
        self.assertEqual(counts["openat2_with_path_field"], 1)
        self.assertEqual(counts["openat2_nonempty_path"], 1)

    def test_grouped_capture_schema_and_group_metadata(self):
        groups = {
            "p4_network": [f"p4_{index}" for index in range(29)],
            "ebpf_syscall_counts": [
                "ebpf_unique_threads",
                *[f"ebpf_signal_{index}" for index in range(34)],
            ],
        }
        network_fields, host_fields = select_feature_fields(groups)
        feature_row = build_feature_row(
            "control.sh",
            {
                "label": "0",
                "class_name": "benign",
                "package_group": "compression",
                "workload_family": "archive-tool",
                "group_id": "compression::archive-tool",
            },
            {"sample_name": "control", "status": "completed", "ebpf_status": "active"},
            [
                {"p4_0": "1", "ebpf_signal_0": "2"},
                {"p4_0": "3", "ebpf_signal_0": "4"},
            ],
            network_fields,
            host_fields,
        )

        self.assertEqual(len(network_fields) * 5, 145)
        self.assertEqual(len(host_fields) * 5, 170)
        self.assertEqual(feature_row["package_group"], "compression")
        self.assertEqual(feature_row["group_id"], "compression::archive-tool")
        self.assertEqual(feature_row["ebpf_status"], "active")
        self.assertEqual(feature_row["network__p4_p4_0__sum"], 4)
        self.assertEqual(feature_row["host__ebpf_signal_0__sum"], 6)

    def test_package_group_and_legacy_package_fields_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            telemetry_path = Path(directory) / "telemetry.csv"
            with telemetry_path.open("w", newline="", encoding="utf-8") as destination:
                writer = csv.DictWriter(
                    destination,
                    fieldnames=[
                        "record_type",
                        "sample_artifact",
                        "net_packets_captured",
                        "host_active_processes",
                    ],
                )
                writer.writeheader()
                writer.writerows(
                    [
                        {
                            "record_type": "telemetry_window",
                            "sample_artifact": "archive-a.sh",
                            "net_packets_captured": 1,
                            "host_active_processes": 2,
                        },
                        {
                            "record_type": "telemetry_window",
                            "sample_artifact": "archive-b.sh",
                            "net_packets_captured": 3,
                            "host_active_processes": 4,
                        },
                    ]
                )

            manifest = {
                "archive-a.sh": {
                    "package_group": "compression",
                    "workload_family": "archive-tool",
                    "group_id": "compression::archive-tool",
                },
                "archive-b.sh": {
                    "package": "system-tools",
                    "workload_family": "utilities",
                },
            }
            examples, _ = load_telemetry(telemetry_path, 0, "benign", manifest)

        by_artifact = {example["sample_artifact"]: example for example in examples}
        self.assertEqual(by_artifact["archive-a.sh"]["package_group"], "compression")
        self.assertEqual(by_artifact["archive-b.sh"]["package_group"], "system-tools")
        self.assertEqual(by_artifact["archive-b.sh"]["group_id"], "system-tools::utilities")


if __name__ == "__main__":
    unittest.main()