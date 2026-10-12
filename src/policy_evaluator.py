"""Limited offline IAM identity-policy evaluator for synthetic lab cases."""

import fnmatch
import json
from pathlib import Path

def evaluate(policy, action, resource):
    """Evaluate supported IAM statements, preserving deny precedence."""
    explicit_allow = False
    unsupported = False
    unsupported_syntax = False

    for statement in policy.get("Statement", []):
        if "NotAction" in statement or "NotResource" in statement:
            unsupported_syntax = True
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        action_matches = any(
            fnmatch.fnmatchcase(action.lower(), pattern.lower())
            for pattern in actions
        )
        resource_matches = any(
            fnmatch.fnmatchcase(resource, pattern)
            for pattern in resources
        )

        if not (action_matches and resource_matches):
            continue

        if "Condition" in statement:
            unsupported = True
            continue

        if statement.get("Effect") == "Deny":
            return "EXPLICIT_DENY"

        if statement.get("Effect") == "Allow":
            explicit_allow = True

    if unsupported or unsupported_syntax:
        return "UNSUPPORTED"

    return "ALLOW" if explicit_allow else "IMPLICIT_DENY"

def load_policy(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


if __name__ == "__main__":
    policy = load_policy("policies/iam-001-baseline.json")

    cases = [
        (
            "Approved dataset",
            "s3:GetObject",
            "arn:aws:s3:::ari-approved-research/report.txt",
        ),
        (
            "Restricted dataset",
            "s3:GetObject",
            "arn:aws:s3:::ari-restricted-research/confidential.txt",
        ),
        (
            "Unrelated bucket",
            "s3:ListBucket",
            "arn:aws:s3:::unrelated-bucket",
        ),
    ]

    for label, action, resource in cases:
        print(f"{label}: {evaluate(policy, action, resource)}")