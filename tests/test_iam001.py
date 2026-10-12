
"""Regression tests for IAM-001 workload identity permissions."""

import unittest

from src.policy_evaluator import evaluate, load_policy


class IAM001Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.baseline = load_policy("policies/iam-001-baseline.json")
        cls.hardened = load_policy("policies/iam-001-hardened.json")

    def test_baseline_allows_approved_object(self):
        result = evaluate(
            self.baseline,
            "s3:GetObject",
            "arn:aws:s3:::ari-approved-research/report.txt",
        )
        self.assertEqual(result, "ALLOW")

    def test_baseline_exposes_restricted_object(self):
        result = evaluate(
            self.baseline,
            "s3:GetObject",
            "arn:aws:s3:::ari-restricted-research/confidential.txt",
        )
        self.assertEqual(result, "ALLOW")

    def test_hardened_preserves_approved_access(self):
        result = evaluate(
            self.hardened,
            "s3:GetObject",
            "arn:aws:s3:::ari-approved-research/report.txt",
        )
        self.assertEqual(result, "ALLOW")

    def test_hardened_denies_restricted_object(self):
        result = evaluate(
            self.hardened,
            "s3:GetObject",
            "arn:aws:s3:::ari-restricted-research/confidential.txt",
        )
        self.assertEqual(result, "IMPLICIT_DENY")

    def test_hardened_denies_unrelated_bucket(self):
        result = evaluate(
            self.hardened,
            "s3:ListBucket",
            "arn:aws:s3:::unrelated-bucket",
        )
        self.assertEqual(result, "IMPLICIT_DENY")


if __name__ == "__main__":
    unittest.main()