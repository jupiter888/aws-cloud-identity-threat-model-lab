
# IAM-003 — Secrets Manager Security Findings

## 1. Security Finding

The fictional Aster Research Institute (ARI) ECS application
workload has excessive AWS Secrets Manager permissions.

The baseline identity policy permits
`secretsmanager:GetSecretValue` against all resources.

A compromised workload could attempt to retrieve secrets
outside its intended authorization scope.

## 2. Threat Classification

- Scenario: IAM-003
- Trust boundary: TB-03
- Threat: Unauthorized secret retrieval
- Affected service: AWS Secrets Manager
- Attacker starting position: Compromised ECS workload

## 3. Baseline and Hardened Results

| Authorization Request | Baseline | Hardened |
|---|---|---|
| Retrieve approved application secret | ALLOW | ALLOW |
| Retrieve restricted administration secret | ALLOW | IMPLICIT_DENY |
| Retrieve unrelated secret | ALLOW | IMPLICIT_DENY |

The hardened policy also implicitly denies
`secretsmanager:DeleteSecret` for the approved secret.

## 4. Implemented Control

### IAM-003-C1: Resource-Scoped Secret Retrieval

The hardened identity policy restricts
`secretsmanager:GetSecretValue` to the fictional application
secret ARN:

`arn:aws:secretsmanager:eu-central-1:111122223333:secret:ari/application/config-??????`

The six question marks match the generated Secrets Manager
ARN suffix.

The policy does not grant secret deletion or unrestricted
access to administrative secrets.

## 5. Validation Evidence

Six automated IAM-003 regression tests passed.

Evidence:
[IAM-003 test results](../../evidence/IAM-003-test-results.txt)

Policies:

- [Baseline policy](../../policies/iam-003-baseline.json)
- [Hardened policy](../../policies/iam-003-hardened.json)

Implementation:

- [Policy evaluator](../../src/policy_evaluator.py)
- [Regression tests](../../tests/test_iam003.py)

## 6. Security Outcome

The hardened policy preserves modeled access to the approved
application secret while removing the two demonstrated
unauthorized retrieval paths.

The regression suite also verifies that secret deletion is
not authorized by the hardened policy.

## 7. Residual Risks and Limitations

- A compromised workload may still retrieve and misuse its
  legitimately authorized application secret.
- The evaluator implements a limited subset of AWS IAM
  identity-policy authorization semantics.
- Matching conditional statements and statements containing
  NotAction or NotResource are flagged as UNSUPPORTED rather
  than treated as definitive authorization decisions.
- UNSUPPORTED indicates an indeterminate offline result,
  not an AWS access-denied decision.
- IAM conditions are not evaluated. Resource policies,
  permissions boundaries, SCPs, and other applicable
  authorization mechanisms are not modeled.
- Unsupported policy syntax may remain undetected; the evaluator
  is not suitable for production authorization decisions.
- KMS permissions and encryption-key access are not evaluated.
- Secret rotation, application-side handling, and runtime
  exposure protections have not been implemented.
- CloudTrail monitoring and alerting remain proposed.
- No live AWS Secrets Manager operations were performed.

## 8. Assessment Status

IAM-003: Implemented and validated within the offline lab.

Production effectiveness: Not established.