from __future__ import annotations

import unittest

import numpy as np

from src.live_arm_inference import build_live_feature_vector


FEATURE_NAMES = [
    "network__net_packets_captured__mean",
    "network__net_packets_captured__max",
    "network__net_packets_captured__sum",
    "network__net_packets_captured__std",
    "network__net_packets_captured__active_windows",
    "host__ebpf_file_write_bytes__mean",
    "host__ebpf_file_write_bytes__max",
    "host__ebpf_file_write_bytes__sum",
    "host__ebpf_file_write_bytes__std",
    "host__ebpf_file_write_bytes__active_windows",
    "arm__network_available",
    "arm__host_available",
]


class LiveArmInferenceTests(unittest.TestCase):
    def setUp(self):
        self.windows = [
            {
                "network": {"net_packets_captured": 2},
                "host": {"ebpf_file_write_bytes": 4},
            },
            {
                "network": {"net_packets_captured": 6},
                "host": {"ebpf_file_write_bytes": 0},
            },
        ]

    def test_hybrid_aggregates_both_modalities_with_population_std(self):
        vector = build_live_feature_vector(self.windows, "hybrid", FEATURE_NAMES)

        np.testing.assert_allclose(
            vector,
            [4, 6, 8, 2, 2, 2, 4, 4, 2, 1, 1, 1],
        )

    def test_each_single_sensor_arm_zeros_unavailable_modality(self):
        p4_vector = build_live_feature_vector(self.windows, "p4_only", FEATURE_NAMES)
        ebpf_vector = build_live_feature_vector(self.windows, "ebpf_only", FEATURE_NAMES)

        np.testing.assert_allclose(p4_vector[5:], [0, 0, 0, 0, 0, 1, 0])
        np.testing.assert_allclose(ebpf_vector[:5], [0, 0, 0, 0, 0])
        np.testing.assert_allclose(ebpf_vector[-2:], [0, 1])

    def test_missing_enabled_feature_fails_instead_of_defaulting_to_zero(self):
        self.windows[0]["host"] = {}

        with self.assertRaisesRegex(ValueError, "missing required host metric"):
            build_live_feature_vector(self.windows, "hybrid", FEATURE_NAMES)

    def test_invalid_arm_and_invalid_counter_fail(self):
        with self.assertRaisesRegex(ValueError, "Unknown arm"):
            build_live_feature_vector(self.windows, "unknown", FEATURE_NAMES)

        self.windows[0]["network"]["net_packets_captured"] = float("nan")
        with self.assertRaisesRegex(ValueError, "invalid network metric"):
            build_live_feature_vector(self.windows, "p4_only", FEATURE_NAMES)


if __name__ == "__main__":
    unittest.main()
