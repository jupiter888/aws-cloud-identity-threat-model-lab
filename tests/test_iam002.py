
"""Regression tests for IAM-002 STS role-assumption controls."""

import unittest

from src.policy_evaluator import load_policy
from src.sts_evaluator import (
    evaluate_assume_role,
    evaluate_trust,
    load_trust_policy,
)


APPLICATION_ROLE = (
    "arn:aws:iam::111122223333:role/ARI-ECS-ApplicationRole"
)

SECURITY_ADMIN = (
    "arn:aws:iam::111122223333:role/ARI-SecurityAdmin"
)

TARGET_ROLE = (
    "arn:aws:iam::111122223333:role/ARI-ResearchAdmin"
)


class IAM002Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.caller_baseline = load_policy(
            "policies/iam-002-caller-baseline.json"
        )
        cls.caller_hardened = load_policy(
            "policies/iam-002-caller-hardened.json"
        )
        cls.trust_baseline = load_trust_policy(
            "policies/iam-002-trust-baseline.json"
        )
        cls.trust_hardened = load_trust_policy(
            "policies/iam-002-trust-hardened.json"
        )

    def test_baseline_exposes_privileged_role(self):
        result = evaluate_assume_role(
            self.caller_baseline,
            self.trust_baseline,
            APPLICATION_ROLE,
            TARGET_ROLE,
        )
        self.assertEqual(result, "ALLOW")

    def test_hardened_caller_blocks_assumption(self):
        result = evaluate_assume_role(
            self.caller_hardened,
            self.trust_baseline,
            APPLICATION_ROLE,
            TARGET_ROLE,
        )
        self.assertEqual(result, "IMPLICIT_DENY")

    def test_hardened_trust_blocks_assumption(self):
        result = evaluate_assume_role(
            self.caller_baseline,
            self.trust_hardened,
            APPLICATION_ROLE,
            TARGET_ROLE,
        )
        self.assertEqual(result, "IMPLICIT_DENY")

    def test_both_controls_block_assumption(self):
        result = evaluate_assume_role(
            self.caller_hardened,
            self.trust_hardened,
            APPLICATION_ROLE,
            TARGET_ROLE,
        )
        self.assertEqual(result, "IMPLICIT_DENY")

    def test_hardened_trust_recognizes_security_admin(self):
        result = evaluate_trust(
            self.trust_hardened,
            SECURITY_ADMIN,
        )
        self.assertEqual(result, "ALLOW")


if __name__ == "__main__":
    unittest.main()