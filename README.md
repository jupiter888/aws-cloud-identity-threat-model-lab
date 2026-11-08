# Project 4 — AWS Cloud Identity Threat Modeling Lab

**AWS IAM Security | Cloud Identity Threat Modeling | Least Privilege | Privilege Escalation | Trust Policies | Security Architecture**

## Overview

An architecture-focused security lab examining identity compromise,
privilege escalation, and excessive AWS resource permissions.

The project models a fictional research organization, Aster Research
Institute (ARI), operating an AI research assistant on Amazon ECS.

Three threat scenarios demonstrate how compromised workload
identities can exploit excessive IAM permissions and unsafe
trust relationships.

Each scenario includes baseline and hardened configurations,
automated regression tests, and documented residual risks.

## Security Scenarios

| ID | Threat | Implemented Mitigation |
|---|---|---|
| IAM-001 | Excessive Amazon S3 permissions | Resource-scoped S3 access |
| IAM-002 | Unauthorized STS role assumption | Caller permission and target-role trust restrictions |
| IAM-003 | Unauthorized Secrets Manager access | Resource-scoped secret retrieval |

## Architecture

[View the architecture diagram](diagrams/cloud-identity-architecture.md)

[Read the system architecture](docs/architecture/system-architecture.md)

The reference architecture includes:

- Amazon ECS application workload
- IAM task role and identity policies
- AWS STS role-assumption relationships
- Amazon S3 research datasets
- AWS Secrets Manager
- Proposed CloudTrail monitoring

All AWS resources and identities are synthetic.

## Threat Models

- [IAM-001: Compromised ECS Workload Identity](docs/threat-model/IAM-001.md)
- [IAM-002: Unauthorized STS Role Assumption](docs/threat-model/IAM-002.md)
- [IAM-003: Unauthorized Secrets Manager Access](docs/threat-model/IAM-003.md)

## Security Findings

- [IAM-001 Findings](docs/security-controls/IAM-001-findings.md)
- [IAM-002 Findings](docs/security-controls/IAM-002-findings.md)
- [IAM-003 Findings](docs/security-controls/IAM-003-findings.md)

## Validation

The lab uses Python-based offline policy evaluators to test
selected IAM identity-policy and STS trust-policy behaviors.

Run the complete regression suite from the repository root:

    python3 -B -m unittest discover -s tests -p 'test_*.py' -v

Recorded validation results:

| Test Group | Passing Tests |
|---|---:|
| IAM-001 | 5 |
| IAM-002 | 5 |
| IAM-003 | 6 |
| Evaluator security tests | 7 |
| Total | 23 |

[Full regression evidence](evidence/full-regression-results.txt)

## Repository Structure

- `diagrams/` — Architecture visualization
- `docs/architecture/` — System architecture
- `docs/threat-model/` — Threat scenarios
- `docs/security-controls/` — Findings and residual risks
- `policies/` — Baseline and hardened IAM policies
- `src/` — Offline authorization evaluators
- `tests/` — Automated regression tests
- `evidence/` — Recorded validation results

## Scope and Limitations

This is a synthetic, offline security architecture lab.

The evaluators implement selected IAM identity-policy and STS
trust-policy behaviors. They are not complete AWS authorization
engines.

The identity-policy evaluator supports action/resource matching,
explicit-deny precedence, and implicit denial for the modeled
scenarios. It detects matching statements with IAM conditions
and statements using NotAction or NotResource, returning
UNSUPPORTED when it cannot establish a reliable decision.

UNSUPPORTED is an indeterminate simulation result, not an AWS
authorization decision or proof that access would be denied.

The evaluators do not comprehensively implement IAM conditions,
resource-based policies, SCPs, permissions boundaries, session
policies, or same-account STS authorization semantics. Some
unsupported policy constructs may still be unrecognized.

The project does not deploy AWS infrastructure, retrieve real
secrets, execute live STS requests, or establish production
security enforcement.

CloudTrail monitoring is proposed but not implemented.

## Security Outcome

The lab demonstrates three modeled authorization weaknesses
and validates corresponding least-privilege mitigations.

The primary deliverables are threat models, mitigation
decisions, policy artifacts, regression tests, and
reproducible security evidence.

## Licensing

This repository uses separate licensing terms for software
and original architecture documentation.

- **Code and synthetic IAM policies:** [MIT License](CODE-LICENSE.md)
- **Architecture, threat models, diagrams, findings, and evidence:** [All Rights Reserved](docs/NOTICE.md)

The MIT License applies exclusively to `src/`, `tests/`,
and `policies/`.

Original architecture documentation and security assessments
may not be reproduced or redistributed without permission,
except where permitted by applicable law.
