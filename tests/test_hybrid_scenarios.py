from __future__ import annotations

import ast
import csv
import json
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from src.build_dataset import (
    assign_malware_family_groups,
    load_telemetry_files,
    load_telemetry,
    read_manifest,
    read_malware_family_metadata,
)
from src.acquire_malwarebazaar_samples import select_candidates
from src.train_compare import class_names_for
from src.analyze_p4_emulated_scenarios import HOST_SIGNAL_CONTRACT, P4_SIGNAL_CONTRACT
from workloads.generate_hybrid_scenarios import build_cohort


class HybridScenarioTests(unittest.TestCase):
    def test_canonical_collector_signal_breadth_is_explicit(self):
        self.assertEqual(len(P4_SIGNAL_CONTRACT), 29)
        self.assertEqual(len(HOST_SIGNAL_CONTRACT), 26)

    def test_candidate_selection_targets_new_tagged_families(self):
        def candidate(digest, signature, tags):
            return {
                "sha256_hash": digest * 64,
                "signature": signature,
                "file_format": "ELF",
                "tags": tags,
            }

        pools = [
            ("backdoor", [
                candidate("a", "BackdoorA", ["backdoor", "elf"]),
                candidate("b", "WrongTag", ["trojan", "elf"]),
            ]),
            ("trojan", [
                candidate("c", "BackdoorA", ["trojan", "elf"]),
                candidate("d", "TrojanB", ["trojan", "elf"]),
            ]),
            ("other_elf", [
                candidate("e", "TaggedBotnet", ["botnet", "elf"]),
                candidate("f", "Uncategorized", ["elf"]),
            ]),
        ]

        selected = select_candidates(pools, set(), set(), set(), per_category=2)

        self.assertEqual(
            [(category, row["signature"]) for category, row in selected],
            [
                ("backdoor", "BackdoorA"),
                ("trojan", "BackdoorA"),
                ("trojan", "TrojanB"),
                ("other_elf", "Uncategorized"),
            ],
        )

    def test_malware_metadata_groups_samples_by_signature(self):
        with tempfile.TemporaryDirectory() as temporary:
            metadata_path = Path(temporary) / "metadata.jsonl"
            additions_path = Path(temporary) / "additions.jsonl"
            metadata = [
                {"sha256": "a" * 64, "signature": "Gafgyt"},
                {"sha256": "b" * 64, "signature": "Gafgyt"},
                {"sha256": "c" * 64, "signature": "Prometei"},
                {"sha256": "d" * 64, "signature": "None"},
            ]
            metadata_path.write_text(
                "\n".join(json.dumps(row) for row in metadata[:2]) + "\n",
                encoding="utf-8",
            )
            additions_path.write_text(
                "\n".join(json.dumps(row) for row in metadata[2:]) + "\n",
                encoding="utf-8",
            )
            family_by_artifact = read_malware_family_metadata([metadata_path, additions_path])
            examples = [
                {"sample_artifact": f"{row['sha256']}.zip", "group_id": "malware::sample"}
                for row in metadata
            ]

            assign_malware_family_groups(examples, family_by_artifact)

        self.assertEqual(
            [example["group_id"] for example in examples],
            [
                "malware_signature::Gafgyt",
                "malware_signature::Gafgyt",
                "malware_signature::Prometei",
                "malware_signature::unassigned",
            ],
        )

    def test_multiple_malware_collectors_combine_with_matching_sensor_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            columns = sorted(
                {
                    "record_type",
                    "sample_artifact",
                    "label",
                    "sample_status",
                    "ebpf_status",
                    "net_packets_captured",
                    "net_bytes_captured",
                    "net_flow_count",
                    "ebpf_connect_count",
                    "ebpf_sendto_count",
                    "ebpf_socket_count",
                    "ebpf_openat_success_count",
                    "ebpf_openat2_success_count",
                    "ebpf_file_write_success_count",
                    "ebpf_file_pwrite64_success_count",
                    "ebpf_file_writev_success_count",
                    "ebpf_file_write_bytes",
                }
            )
            paths = [root / "baseline.csv", root / "addition.csv"]
            for index, path in enumerate(paths):
                with path.open("w", newline="", encoding="utf-8") as destination:
                    writer = csv.DictWriter(destination, fieldnames=columns)
                    writer.writeheader()
                    writer.writerow(
                        {
                            "record_type": "telemetry_window",
                            "sample_artifact": f"{index:064x}.zip",
                            "label": "malware",
                            "sample_status": "completed",
                            "ebpf_status": "active",
                            **{column: "1" for column in columns if column.startswith(("net_", "ebpf_"))},
                        }
                    )

            examples, feature_groups = load_telemetry_files(paths, 1, "malware")

        self.assertEqual(len(examples), 2)
        self.assertEqual(len(feature_groups["network"]), 3)
        self.assertEqual(len(feature_groups["host"]), 9)

    def test_training_reports_manifest_class_names(self):
        examples = [
            {"label": "0", "class_name": "benign_control"},
            {"label": "1", "class_name": "attack_simulation"},
        ]

        self.assertEqual(
            class_names_for(examples),
            {0: "benign_control", 1: "attack_simulation"},
        )

    def test_generated_conditions_are_paired_and_internal_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = build_cohort(root / "workloads", root / "manifest.csv", replicates=2)

            self.assertEqual(len(rows), 30)
            self.assertEqual(Counter(row["label"] for row in rows), {"1": 10, "0": 20})
            groups = defaultdict(set)
            for row in rows:
                groups[row["group_id"]].add(row["label"])
                script = root / "workloads" / row["sample_artifact"]
                script_text = script.read_text(encoding="utf-8")
                ast.parse(script_text)
                self.assertIn('TARGET_IP = "10.0.0.255"', script_text)
                self.assertIn("connection.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)", script_text)
                self.assertEqual(script_text.count("time.sleep(0.25)"), 2)
                self.assertIn("connection.sendto(payload[:size], (destination, port))", script_text)
                self.assertEqual(row["file_bytes"], row["payload_bytes"])
                if row["condition"] == "benign_file_only":
                    self.assertIn('else "127.0.0.1"', script_text)
            self.assertEqual(len(groups), 5)
            self.assertTrue(all(labels == {"0", "1"} for labels in groups.values()))

    def test_p4_addition_pack_is_protocol_diverse_and_internal_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = build_cohort(
                root / "workloads",
                root / "manifest.csv",
                replicates=2,
                scenario_pack="p4-additions",
            )

            self.assertEqual(len(rows), 30)
            self.assertEqual(
                {row["scenario_id"] for row in rows},
                {
                    "udp_dns_query",
                    "udp_payload_mix",
                    "udp_timed_burst",
                    "tcp_connect",
                    "tcp_connect_fanout",
                },
            )
            self.assertEqual({row["protocol"] for row in rows}, {"udp", "tcp"})
            self.assertEqual({row["target_ip"] for row in rows}, {"10.0.0.1"})
            self.assertEqual(Counter(row["label"] for row in rows), {"1": 10, "0": 20})
            for row in rows:
                script = root / "workloads" / row["sample_artifact"]
                text = script.read_text(encoding="utf-8")
                ast.parse(text)
                self.assertIn('TARGET_IP = "10.0.0.1"', text)
                self.assertNotIn("subprocess", text)
                self.assertNotIn("os.system", text)
                self.assertIn("127.0.0.1", text)

    def test_scenario_manifest_builds_group_held_out_examples(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = build_cohort(root / "workloads", root / "manifest.csv", replicates=2)
            manifest = read_manifest(root / "manifest.csv")
            telemetry = root / "combined.csv"
            fields = [
                "record_type", "sample_artifact", "sample_name", "sample_status",
                "net_packets_captured", "net_bytes_captured", "net_flow_count",
                "ebpf_connect_count", "ebpf_sendto_count", "ebpf_socket_count",
                "ebpf_openat_success_count", "ebpf_write_count", "ebpf_file_write_success_count",
                "ebpf_file_write_bytes", "ebpf_status",
            ]
            with telemetry.open("w", newline="", encoding="utf-8") as destination:
                writer = csv.DictWriter(destination, fieldnames=fields)
                writer.writeheader()
                for item in rows:
                    has_network = item["condition"] != "benign_file_only"
                    has_file_activity = item["condition"] != "benign_network_only"
                    writer.writerow(
                        {
                            "record_type": "telemetry_window",
                            "sample_artifact": item["sample_artifact"],
                            "sample_name": item["sample_artifact"],
                            "sample_status": "completed",
                            "net_packets_captured": 5 if has_network else 0,
                            "net_bytes_captured": int(item["payload_bytes"]) if has_network else 0,
                            "net_flow_count": 1 if has_network else 0,
                            "ebpf_connect_count": 0,
                            "ebpf_sendto_count": 1,
                            "ebpf_socket_count": 1,
                            "ebpf_openat_success_count": 1 if has_file_activity else 0,
                            "ebpf_write_count": 1 if has_file_activity else 0,
                            "ebpf_file_write_success_count": 1 if has_file_activity else 0,
                            "ebpf_file_write_bytes": int(item["payload_bytes"]) if has_file_activity else 0,
                            "ebpf_status": "active",
                        }
                    )

            examples, feature_groups = load_telemetry(telemetry, None, None, manifest)
            labels = np.asarray([row["label"] for row in examples], dtype=int)
            groups = np.asarray([row["group_id"] for row in examples], dtype=str)
            self.assertEqual(Counter(labels), {1: 10, 0: 20})
            self.assertEqual(len(feature_groups["network"]), 3)
            self.assertEqual(len(feature_groups["host"]), 6)
            self.assertNotIn("ebpf_write_count", feature_groups["host"])
            paired_examples = defaultdict(dict)
            for example in examples:
                paired_examples[(example["pair_id"], example["variant"])][example["condition"]] = example
            network_columns = [name for name in examples[0] if name.startswith("network__")]
            host_columns = [name for name in examples[0] if name.startswith("host__")]
            for conditions in paired_examples.values():
                attack = conditions["attack_simulation"]
                file_only = conditions["benign_file_only"]
                network_only = conditions["benign_network_only"]
                self.assertEqual(
                    [attack[name] for name in host_columns],
                    [file_only[name] for name in host_columns],
                )
                self.assertEqual(
                    [attack[name] for name in network_columns],
                    [network_only[name] for name in network_columns],
                )
            splits = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42).split(
                np.zeros((len(labels), 1)), labels, groups
            )
            for train_indices, test_indices in splits:
                self.assertFalse(set(groups[train_indices]) & set(groups[test_indices]))
                self.assertEqual(set(labels[test_indices]), {0, 1})


if __name__ == "__main__":
    unittest.main()
