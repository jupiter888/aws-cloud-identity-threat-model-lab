
# IAM-001 — Security Findings and Control Validation

## Finding

The fictional AI research assistant's baseline IAM identity policy
grants excessive S3 permissions through a wildcard resource scope.

A compromised application workload could misuse those permissions
to request research objects outside its intended authorization scope.

## Baseline and Hardened Results

| Authorization Request | Baseline | Hardened |
|---|---|---|
| Read approved research object | ALLOW | ALLOW |
| Read restricted research object | ALLOW | IMPLICIT_DENY |
| List unrelated S3 bucket | ALLOW | IMPLICIT_DENY |

## Implemented Control

The hardened identity policy restricts:

- `s3:GetObject` to objects in the approved research bucket.
- `s3:ListBucket` to the approved research bucket.

No wildcard resource permission is granted.

## Validation Evidence

Five automated regression tests passed using the project's
limited offline IAM identity-policy evaluator.

Evidence: [IAM-001 test results](../../evidence/IAM-001-test-results.txt)

Policies:

- [Baseline policy](../../policies/iam-001-baseline.json)
- [Hardened policy](../../policies/iam-001-hardened.json)

Implementation:

- [Policy evaluator](../../src/policy_evaluator.py)
- [Regression tests](../../tests/test_iam001.py)

## Security Outcome

The hardened policy preserves the demonstrated authorized
operation while eliminating two unnecessary permissions.

This represents reduced authorization scope in the modeled
identity-policy evaluation.

## Residual Risks and Limitations

- A compromised workload can still misuse legitimately authorized access.

- The evaluator implements a limited subset of AWS IAM
  identity-policy authorization semantics.
- Matching conditional statements and statements containing
  NotAction or NotResource are flagged as UNSUPPORTED rather
  than treated as definitive authorization decisions.
- UNSUPPORTED indicates an indeterminate offline result,
  not an AWS access-denied decision.
- IAM conditions are not evaluated. Resource policies, service
  control policies, permissions boundaries, session policies,
  and other applicable authorization mechanisms are not modeled.
- Unsupported policy syntax may remain undetected; the evaluator
  is not suitable for production authorization decisions.
- No live AWS access or cloud-side enforcement was tested.
- Logging and detection controls remain proposed rather than validated.

## Assessment Status

IAM-001: Implemented and validated within the offline lab.

Production effectiveness: Not established.