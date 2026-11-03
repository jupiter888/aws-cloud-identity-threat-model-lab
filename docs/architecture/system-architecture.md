# Cloud Identity Compromise — System Architecture

## 1. System Purpose

Aster Research Institute (ARI) operates a fictional AWS-hosted AI research assistant that retrieves approved research documents.

The reference architecture examines identity compromise, excessive IAM permissions, unauthorized resource access, privilege escalation, and blast-radius reduction.

All identities, resources, and datasets are synthetic. The application and AWS infrastructure are architectural representations; policy artifacts and selected authorization behaviors are implemented and tested offline.

## 2. Architecture Components

- **Research Users:** Represent authenticated users accessing the internal research assistant.
- **Amazon ECS:** Represents the hosting environment for the AI application workload.
- **IAM Task Role:** Represents the application's workload identity and temporary AWS credentials.
- **AWS STS:** Represents temporary security credentials and role-assumption operations.
- **Privileged ResearchAdmin Role:** Represents a privileged target role examined in the role-assumption scenario.
- **SecurityAdmin Role:** Represents the dedicated administrative principal permitted by the hardened ResearchAdmin trust policy.
- **Amazon S3:** Represents approved and restricted synthetic research datasets.
- **AWS Secrets Manager:** Represents application and administration secrets and their access boundaries.
- **AWS CloudTrail:** Represents a proposed source of audit events. Monitoring and alerting are not implemented.

## 3. Trust Boundaries

**TB-01 — User to Application**

User requests enter the application boundary. Authentication and application authorization are architectural requirements and are not implemented or tested in this lab.

**TB-02 — Application to AWS Identity**

Application code operates using permissions assigned to its ECS task role. A compromised workload may misuse those permissions.

**TB-03 — Workload Identity to Data Resources**

IAM and other applicable authorization controls govern access to S3 datasets and Secrets Manager resources. The offline lab evaluates selected identity-policy behaviors only.

**TB-04 — Identity to Role Assumption**

Caller permissions and target-role trust govern the modeled role-assumption decision. The offline evaluator does not reproduce the complete AWS STS authorization process.

**TB-05 — Workload to Audit Infrastructure**

Security-relevant API activity should be observable through appropriately configured audit services. CloudTrail monitoring and detection remain proposed.

## 4. Threat Scenarios

All three scenarios assume that an attacker has compromised the fictional application workload and can attempt operations using its available identity. Application exploitation, credential extraction, and live AWS operations are not demonstrated.

### IAM-001 — Excessive S3 Permissions

**Threat:** Misuse of the application's workload identity to access research data beyond its intended scope.

**Attack objective:** Read a synthetic S3 object from a restricted research dataset.

**Baseline weakness:** The identity policy permits `s3:GetObject` and `s3:ListBucket` against all resources.

**Implemented mitigation:** The hardened policy limits object reads and bucket listing to the approved research bucket.

**Offline validation:** Five regression tests demonstrate baseline exposure, preservation of approved object access, and implicit denial of selected restricted or unrelated requests under the hardened policy.

### IAM-002 — Unauthorized STS Role Assumption

**Threat:** Privilege escalation from the compromised application workload to a privileged research administration role.

**Attack objective:** Assume the fictional ResearchAdmin role.

**Baseline weakness:** The caller policy permits `sts:AssumeRole` for ResearchAdmin, and the target-role trust policy permits the application role.

**Implemented mitigations:** The hardened caller policy grants no role-assumption permission. The hardened target-role trust policy permits SecurityAdmin instead of the application role.

**Offline validation:** Five regression tests demonstrate baseline exposure, independent and combined restriction of the application's modeled role-assumption request, and recognition of SecurityAdmin by the hardened trust policy. Successful role assumption by SecurityAdmin is not independently established.

### IAM-003 — Unauthorized Secrets Manager Access

**Threat:** Misuse of the application's workload identity to retrieve secrets beyond its intended scope.

**Attack objective:** Retrieve a synthetic administration secret.

**Baseline weakness:** The identity policy permits `secretsmanager:GetSecretValue` against all resources.

**Implemented mitigation:** The hardened policy limits retrieval to the fictional application secret ARN pattern.

**Offline validation:** Six regression tests demonstrate baseline exposure, preservation of approved secret retrieval, and implicit denial of restricted secret retrieval, unrelated secret retrieval, and secret deletion under the hardened policy.

## 5. Security Controls and Implementation Status

### Implemented Policy Artifacts

- **IAM-001:** Separate baseline and hardened identity policies demonstrate excessive and resource-scoped S3 permissions.
- **IAM-002:** Separate baseline and hardened caller and trust policies demonstrate restriction of privileged-role assumption.
- **IAM-003:** Separate baseline and hardened identity policies demonstrate excessive and resource-scoped secret retrieval.
- **Offline validation:** Python evaluators and automated regression tests assess selected authorization behaviors and evaluator security properties.

These are implemented lab artifacts. They are not deployed AWS controls.

### Architectural Intentions

- Use temporary workload credentials rather than long-lived application access keys.
- Separate application and administrative identities.
- Require authentication and application authorization at the user-to-application boundary.
- Account for all applicable authorization controls in a production implementation.

These intentions are represented in the architecture but are not deployed or validated as runtime controls.

### Proposed Monitoring

- Collect relevant CloudTrail events.
- Detect unexpected S3 access, privileged-role assumption attempts, and Secrets Manager access.
- Define alerting and investigation procedures.

Logging, detection, and alerting are not implemented or validated.

## 6. Validation Strategy

The project compares deliberately insecure and hardened policy configurations using offline tests.

Tests assess selected authorization behaviors; they do not constitute comprehensive AWS authorization evaluation or live enforcement.

The regression suite contains:

| Test Group | Passing Tests |
|---|---:|
| IAM-001 | 5 |
| IAM-002 | 5 |
| IAM-003 | 6 |
| Evaluator security tests | 7 |
| Total | 23 |

Run the complete suite from the repository root:

    python3 -B -m unittest discover -s tests -p 'test_*.py' -v

Recorded results are preserved in `evidence/full-regression-results.txt`.

The identity-policy evaluator supports selected action/resource matching, explicit-deny precedence, and implicit denial. It returns `UNSUPPORTED` for certain unsupported constructs, including matching conditional statements and statements using `NotAction` or `NotResource`.

`UNSUPPORTED` is an indeterminate offline result, not an AWS access-denied decision.

The STS evaluator models selected caller-policy and target-role trust checks. It does not comprehensively detect or evaluate advanced trust-policy syntax or reproduce complete AWS role-assumption semantics.

The evaluators do not comprehensively model resource-based policies, service control policies, permissions boundaries, session policies, IAM conditions, or other applicable authorization mechanisms. Some unsupported constructs may remain unrecognized.

## 7. Project Constraints

- No production AWS accounts or company infrastructure.
- No real credentials, secret values, or personal data.
- No paid cloud resources required.
- No live application compromise, credential extraction, or AWS API operations.
- No claims of production deployment or comprehensive security validation.

## 8. Implementation Status

**Status:** Reference architecture documented; IAM policy mitigations and offline authorization tests implemented.

Baseline and hardened policy artifacts address excessive S3 permissions (IAM-001), unauthorized role assumption (IAM-002), and unauthorized Secrets Manager access (IAM-003).

Recorded regression results report 23 passing tests: 5 for IAM-001, 5 for IAM-002, 6 for IAM-003, and 7 evaluator security tests.

The ECS application, AWS resources, and STS operations are architectural representations only. CloudTrail monitoring is proposed and not implemented.

Offline evaluation demonstrates selected modeled authorization outcomes. It does not establish production AWS enforcement.
