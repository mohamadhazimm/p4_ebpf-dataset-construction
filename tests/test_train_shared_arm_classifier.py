from __future__ import annotations

import unittest

import numpy as np

from src.train_shared_arm_classifier import (
    ARMS,
    augment_modalities,
    metrics_with_class_errors,
)


class SharedArmClassifierTests(unittest.TestCase):
    def test_augmentation_masks_only_disabled_modality_and_keeps_group(self):
        examples = [
            {
                "network__packets__mean": "8",
                "host__writes__mean": "3",
                "label": "1",
                "class_name": "malware",
                "group_id": "sample-family-a",
                "sample_artifact": "sample-a",
            },
            {
                "network__packets__mean": "2",
                "host__writes__mean": "5",
                "label": "0",
                "class_name": "benign",
                "group_id": "benign-package-b",
                "sample_artifact": "sample-b",
            },
        ]
        feature_sets = {
            "network": ["network__packets__mean"],
            "host": ["host__writes__mean"],
            "hybrid": ["network__packets__mean", "host__writes__mean"],
        }

        features, labels, groups, arms, feature_names = augment_modalities(
            examples, feature_sets
        )

        self.assertEqual(ARMS, ("p4_only", "ebpf_only", "hybrid"))
        self.assertEqual(
            feature_names,
            [
                "network__packets__mean",
                "host__writes__mean",
                "arm__network_available",
                "arm__host_available",
            ],
        )
        np.testing.assert_array_equal(
            features,
            np.asarray(
                [
                    [8, 0, 1, 0],
                    [0, 3, 0, 1],
                    [8, 3, 1, 1],
                    [2, 0, 1, 0],
                    [0, 5, 0, 1],
                    [2, 5, 1, 1],
                ],
                dtype=float,
            ),
        )
        np.testing.assert_array_equal(labels, [1, 1, 1, 0, 0, 0])
        np.testing.assert_array_equal(
            groups,
            [
                "sample-family-a",
                "sample-family-a",
                "sample-family-a",
                "benign-package-b",
                "benign-package-b",
                "benign-package-b",
            ],
        )
        np.testing.assert_array_equal(
            arms,
            ["p4_only", "ebpf_only", "hybrid", "p4_only", "ebpf_only", "hybrid"],
        )

    def test_metrics_include_per_class_error_counts_and_rates(self):
        result = metrics_with_class_errors(
            np.asarray([0, 0, 1, 1]),
            np.asarray([0.2, 0.8, 0.7, 0.1]),
        )

        self.assertEqual((result["tn"], result["fp"], result["fn"], result["tp"]), (1, 1, 1, 1))
        self.assertEqual(result["benign_false_positive_rate"], 0.5)
        self.assertEqual(result["malware_miss_rate"], 0.5)
        self.assertEqual(result["balanced_accuracy"], 0.5)


if __name__ == "__main__":
    unittest.main()
