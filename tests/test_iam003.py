
"""Regression tests for IAM-003 Secrets Manager least privilege."""

import unittest

from src.policy_evaluator import evaluate, load_policy


ACTION = "secretsmanager:GetSecretValue"

APPROVED = (
    "arn:aws:secretsmanager:eu-central-1:111122223333:"
    "secret:ari/application/config-Ab12Cd"
)

RESTRICTED = (
    "arn:aws:secretsmanager:eu-central-1:111122223333:"
    "secret:ari/admin/credentials-Ef34Gh"
)

UNRELATED = (
    "arn:aws:secretsmanager:eu-central-1:111122223333:"
    "secret:unrelated/service-key-Ij56Kl"
)


class IAM003Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.baseline = load_policy(
            "policies/iam-003-baseline.json"
        )
        cls.hardened = load_policy(
            "policies/iam-003-hardened.json"
        )

    def test_baseline_allows_approved_secret(self):
        self.assertEqual(
            evaluate(self.baseline, ACTION, APPROVED),
            "ALLOW",
        )

    def test_baseline_exposes_restricted_secret(self):
        self.assertEqual(
            evaluate(self.baseline, ACTION, RESTRICTED),
            "ALLOW",
        )

    def test_hardened_preserves_approved_access(self):
        self.assertEqual(
            evaluate(self.hardened, ACTION, APPROVED),
            "ALLOW",
        )

    def test_hardened_denies_restricted_secret(self):
        self.assertEqual(
            evaluate(self.hardened, ACTION, RESTRICTED),
            "IMPLICIT_DENY",
        )

    def test_hardened_denies_unrelated_secret(self):
        self.assertEqual(
            evaluate(self.hardened, ACTION, UNRELATED),
            "IMPLICIT_DENY",
        )

    def test_hardened_denies_secret_deletion(self):
        self.assertEqual(
            evaluate(
                self.hardened,
                "secretsmanager:DeleteSecret",
                APPROVED,
            ),
            "IMPLICIT_DENY",
        )


if __name__ == "__main__":
    unittest.main()