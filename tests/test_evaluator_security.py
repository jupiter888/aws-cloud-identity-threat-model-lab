"""Security regression tests for the limited IAM and STS evaluators."""

import unittest

from src.policy_evaluator import evaluate
from src.sts_evaluator import evaluate_trust, evaluate_assume_role


CALLER = "arn:aws:iam::111122223333:role/ARI-ECS-ApplicationRole"
TARGET = "arn:aws:iam::111122223333:role/ARI-ResearchAdmin"


class EvaluatorSecurityTests(unittest.TestCase):
    
    def test_unsupported_notaction_and_notresource(self):
        policies = [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "NotAction": "s3:DeleteObject",
                        "Resource": "*",
                    }
                ]
            },
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "NotResource": "arn:aws:s3:::restricted/*",
                    }
                ]
            },
        ]

        for policy in policies:
            with self.subTest(policy=policy):
                result = evaluate(
                    policy,
                    "s3:GetObject",
                    "arn:aws:s3:::ari-approved-research/report.txt",
                )
                self.assertEqual(result, "UNSUPPORTED")

    
    def test_explicit_deny_overrides_unsupported_condition(self):
        resource = "arn:aws:s3:::ari-restricted-research/secret.txt"

        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalTag/Department": "Research"
                        }
                    },
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:GetObject",
                    "Resource": resource,
                },
            ]
        }

        result = evaluate(
            policy,
            "s3:GetObject",
            resource,
        )

        self.assertEqual(result, "EXPLICIT_DENY")

    def test_unsupported_condition_must_not_allow(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalTag/Department": "Research"
                        }
                    },
                }
            ]
        }

        result = evaluate(
            policy,
            "s3:GetObject",
            "arn:aws:s3:::ari-approved-research/report.txt",
        )

        self.assertNotEqual(result, "ALLOW")

    def test_identity_explicit_deny_overrides_allow(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::ari-restricted-research/*",
                },
            ]
        }

        result = evaluate(
            policy,
            "s3:GetObject",
            "arn:aws:s3:::ari-restricted-research/secret.txt",
        )
        self.assertEqual(result, "EXPLICIT_DENY")

    def test_unmatched_identity_action_is_denied(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ]
        }

        result = evaluate(
            policy,
            "s3:DeleteObject",
            "arn:aws:s3:::ari-approved-research/report.txt",
        )
        self.assertEqual(result, "IMPLICIT_DENY")

    def test_trust_explicit_deny_overrides_allow(self):
        trust = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": CALLER},
                    "Action": "sts:AssumeRole",
                },
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": CALLER},
                    "Action": "sts:AssumeRole",
                },
            ]
        }

        result = evaluate_trust(trust, CALLER)
        self.assertEqual(result, "EXPLICIT_DENY")

    def test_assume_role_respects_trust_explicit_deny(self):
        caller_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": TARGET,
                }
            ]
        }

        trust = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": CALLER},
                    "Action": "sts:AssumeRole",
                }
            ]
        }

        result = evaluate_assume_role(
            caller_policy, trust, CALLER, TARGET
        )
        self.assertEqual(result, "EXPLICIT_DENY")


if __name__ == "__main__":
    unittest.main()