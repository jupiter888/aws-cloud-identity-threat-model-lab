# Cloud Identity Compromise — System Architecture

## 1. System Purpose

Aster Research Institute (ARI) operates a fictional AWS-hosted AI research assistant that retrieves approved research documents.

The architecture is designed to examine identity compromise, excessive IAM permissions, unauthorized resource access, and blast-radius reduction.

All identities, resources, and datasets are synthetic.

## 2. Architecture Components

- **Research Users:** Authenticated users accessing the internal research assistant.
- **Amazon ECS:** Hosts the AI application workload.
- **IAM Task Role:** Supplies temporary AWS credentials to the application.
- **AWS STS:** Supports temporary security credentials and authorized role assumption.
- **Amazon S3:** Stores synthetic research datasets.
- **AWS Secrets Manager:** Represents application secrets and their access boundaries.
- **AWS CloudTrail:** Provides a proposed source of audit events.

## 3. Trust Boundaries

**TB-01 — User to Application**

User requests enter the application boundary. Authentication and application authorization are required.

**TB-02 — Application to AWS Identity**

Application code operates using permissions assigned to its ECS task role. A compromised workload may misuse those permissions.

**TB-03 — Workload Identity to Data Resources**

IAM and resource policies govern access to S3 datasets and Secrets Manager resources.

**TB-04 — Identity to Role Assumption**

IAM trust policies and authorization determine whether a principal can assume another role.

**TB-05 — Workload to Audit Infrastructure**

Security-relevant API activity must be observable through appropriately configured audit services.

## 4. Initial Threat Scenario

**Scenario ID:** IAM-001

**Threat:** Compromise of the AI application's workload identity.

**Attack objective:** Access a synthetic S3 dataset outside the application's intended authorization scope.

**Potential weakness:** Excessively broad IAM permissions.

**Security objective:** Restrict workload permissions to explicitly approved resources and operations.

## 5. Proposed Security Controls

- Least-privilege IAM identity policies.
- Resource-specific S3 authorization.
- Restrictive IAM role trust policies.
- Temporary credentials rather than long-lived access keys.
- Separation of application and administrative identities.
- Audit logging and detection for unexpected access.

## 6. Validation Strategy

The project will compare deliberately insecure and hardened policy configurations using offline tests.

Tests will assess expected authorization decisions for permitted and prohibited actions.

Simulated policy evaluation will be distinguished from live AWS enforcement.

## 7. Project Constraints

- No production AWS accounts or company infrastructure.
- No real credentials, secrets, or personal data.
- No paid cloud resources required.
- No claims of production deployment or comprehensive security validation.

## 8. Implementation Status

**Status:** Reference architecture proposed.

IAM policies, threat-model analysis, and security validation have not yet been implemented.