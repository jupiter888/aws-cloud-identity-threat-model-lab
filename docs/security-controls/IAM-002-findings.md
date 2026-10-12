
# IAM-002 — STS Role Assumption Security Findings

## 1. Security Finding

The fictional Aster Research Institute (ARI) ECS application
workload is authorized to assume a privileged research
administration role.

The baseline configuration combines:

- Caller permission to invoke `sts:AssumeRole`.
- Target-role trust permitting the ECS application identity.

Within the lab's simplified authorization model, a compromised
application workload can cross the privileged-role trust boundary.

## 2. Threat Classification

- Scenario: IAM-002
- Trust boundary: TB-04
- Threat: Unauthorized privilege escalation
- Affected service: AWS IAM / STS
- Attacker starting position: Compromised ECS application workload

## 3. Baseline and Hardened Results

| Caller Policy | Trust Policy | Result |
|---|---|---|
| Baseline | Baseline | ALLOW |
| Hardened | Baseline | IMPLICIT_DENY |
| Baseline | Hardened | IMPLICIT_DENY |
| Hardened | Hardened | IMPLICIT_DENY |

## 4. Implemented Controls

### Control IAM-002-C1: Caller Permission Restriction

The hardened caller policy grants no `sts:AssumeRole`
permission to the ECS application workload.

### Control IAM-002-C2: Target Role Trust Restriction

The hardened ResearchAdmin trust policy authorizes the
dedicated SecurityAdmin role instead of the ECS application role.

These controls are independently tested in the offline model.

## 5. Validation Evidence

Five automated IAM-002 regression tests passed.

Evidence:
[IAM-002 test results](../../evidence/IAM-002-test-results.txt)

Policies:

- [Baseline caller](../../policies/iam-002-caller-baseline.json)
- [Hardened caller](../../policies/iam-002-caller-hardened.json)
- [Baseline trust](../../policies/iam-002-trust-baseline.json)
- [Hardened trust](../../policies/iam-002-trust-hardened.json)

Implementation:

- [STS evaluator](../../src/sts_evaluator.py)
- [Regression tests](../../tests/test_iam002.py)

## 6. Security Outcome

The modeled baseline permits the compromised workload to
assume the privileged role.

Each hardened control independently prevents the modeled
role-assumption request.

The hardened trust policy also recognizes SecurityAdmin as
an authorized principal. Successful role assumption by that
principal was not independently established.

## 7. Residual Risks and Limitations

- The offline STS evaluator models selected caller-policy and
  role-trust checks, not the complete AWS role-assumption
  authorization process.
- The identity-policy evaluator identifies certain unsupported
  constructs, but the trust-policy evaluator does not
  comprehensively detect or evaluate IAM conditions, principal
  variations, or other advanced trust-policy syntax.
- Same-account role-assumption semantics, session policies,
  permissions boundaries, and organizational controls are not
  comprehensively modeled.
- Offline ALLOW and IMPLICIT_DENY results describe the modeled
  checks only; they do not establish actual AWS authorization.
- Other applicable policies could affect effective permissions.
- Compromise of an authorized administrator remains possible.
- CloudTrail detection and alerting have not been implemented.
- No live AWS STS request or cloud-side enforcement was tested.

## 8. Assessment Status

IAM-002: Implemented and validated within the offline lab.

Production effectiveness: Not established.