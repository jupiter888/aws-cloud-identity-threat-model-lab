
# Cloud Identity Security Architecture

## System Context and Trust Boundaries

```mermaid
flowchart TD
    U["Research User"]
    APP["AI Research Assistant<br/>Amazon ECS"]
    ROLE["ECS Application Task Role"]
    STS["AWS STS"]
    ADMIN["Privileged ResearchAdmin Role"]
    S3A["Approved Research<br/>Amazon S3"]
    S3R["Restricted Research<br/>Amazon S3"]
    SMA["Application Secret<br/>Secrets Manager"]
    SMR["Administration Secret<br/>Secrets Manager"]
    CT["AWS CloudTrail<br/>Proposed Monitoring"]

    U -->|"TB-01: Application Access"| APP
    APP -->|"TB-02: Workload Identity"| ROLE

    ROLE -->|"IAM-001: Authorized Read"| S3A
    ROLE -.->|"IAM-001: Restricted"| S3R

    ROLE -->|"IAM-002: AssumeRole Attempt"| STS
    STS -.->|"Hardened Trust Restriction"| ADMIN

    ROLE -->|"IAM-003: Authorized Retrieval"| SMA
    ROLE -.->|"IAM-003: Restricted"| SMR

    STS -.-> CT
    S3A -.-> CT
    SMA -.-> CT
```

## Security Controls

- **IAM-001:** Resource-scoped S3 permissions prevent modeled unauthorized access to restricted research datasets.
- **IAM-002:** Caller permissions and target-role trust restrictions prevent modeled unauthorized privileged-role assumption.
- **IAM-003:** Resource-scoped Secrets Manager permissions prevent modeled retrieval of unrelated secrets.

Solid arrows represent intended or permitted relationships.

Dashed arrows represent restricted paths or proposed monitoring relationships, as indicated by their labels.

## Implementation Status

The IAM policies and authorization tests are implemented in a synthetic offline lab.

The ECS application, AWS resources, STS operations, and CloudTrail monitoring are architectural representations only.

No live AWS deployment or production enforcement has been validated.