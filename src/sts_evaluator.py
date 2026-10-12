
"""Limited offline evaluator for synthetic STS role-assumption cases."""

import json
from pathlib import Path

from src.policy_evaluator import evaluate


def load_trust_policy(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate_trust(trust_policy, principal, action="sts:AssumeRole"):
    """Evaluate simple AWS-principal trust statements."""
    explicit_allow = False

    for statement in trust_policy.get("Statement", []):
        principals = statement.get("Principal", {}).get("AWS", [])
        actions = statement.get("Action", [])

        if isinstance(principals, str):
            principals = [principals]
        if isinstance(actions, str):
            actions = [actions]

        if principal not in principals or action not in actions:
            continue

        if statement.get("Effect") == "Deny":
            return "EXPLICIT_DENY"

        if statement.get("Effect") == "Allow":
            explicit_allow = True

    return "ALLOW" if explicit_allow else "IMPLICIT_DENY"


def evaluate_assume_role(caller_policy, trust_policy, principal, target_role):
    """Require both modeled authorization checks to allow assumption."""
    caller_result = evaluate(
        caller_policy,
        "sts:AssumeRole",
        target_role,
    )

    trust_result = evaluate_trust(
        trust_policy,
        principal,
    )

    if "EXPLICIT_DENY" in (caller_result, trust_result):
        return "EXPLICIT_DENY"

    if caller_result == "ALLOW" and trust_result == "ALLOW":
        return "ALLOW"

    return "IMPLICIT_DENY"