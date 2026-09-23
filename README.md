# Session-Bound API Key Rotation via Usage-Pattern Fingerprinting

A behavior-driven API security prototype that detects abnormal API-key usage patterns and automatically rotates suspicious API credentials.

The system establishes a behavioral baseline for each API key, analyzes incoming requests using usage-pattern features, detects anomalous behavior with an Isolation Forest model, calculates a security risk score, and automatically revokes and replaces a compromised API key when the configured risk threshold is exceeded.

> **Note:** This is a research/academic prototype designed for local experimentation and demonstration. It is not a production secrets-management or KMS/HSM system.

---

## Overview

Traditional API-key rotation is commonly based on fixed schedules or manual intervention.

This project explores a behavior-driven approach in which API-key usage is continuously monitored. Instead of relying only on time-based rotation, the system evaluates changes in how a credential is being used.

The prototype analyzes characteristics such as:

- Request timing
- Endpoint usage
- Request behavior
- Client fingerprint
- Payload-related features
- Historical usage patterns

When sufficiently abnormal behavior is detected, the system:

1. Calculates an anomaly score.
2. Calculates a security risk score.
3. Determines whether the risk threshold has been exceeded.
4. Revokes the existing API key.
5. Generates a new session-bound API key.
6. Records the rotation event in the audit log.
7. Allows the new key to continue legitimate access.

---

## Architecture

```text
                         +------------------+
                         |      Client      |
                         +--------+---------+
                                  |
                                  v
                         +------------------+
                         |   API Gateway    |
                         |    FastAPI       |
                         +--------+---------+
                                  |
                                  v
                     +------------------------+
                     | Request / Usage        |
                     | Profiler               |
                     +-----------+------------+
                                 |
                +----------------+----------------+
                |                                 |
                v                                 v
      +-------------------+             +-------------------+
      | Behavioral        |             | Audit Logging     |
      | Feature Extraction|             |                   |
      +---------+---------+             +-------------------+
                |
                v
      +-------------------+
      | Isolation Forest  |
      | Anomaly Detection |
      +---------+---------+
                |
                v
      +-------------------+
      | Risk Scoring &    |
      | Decision Engine   |
      +---------+---------+
                |
                | High Risk
                v
      +-------------------+
      |     Key Vault     |
      +---------+---------+
                |
        +-------+--------+
        |                |
        v                v
  Revoke Old Key   Generate New
                   Session-Bound Key

---

## Verification

The project includes automated tests covering:

- API health check
- API-key issuance
- Authorized API access
- Normal traffic handling
- Behavioral anomaly detection
- Automatic key rotation
- Old-key revocation
- Missing/invalid API-key rejection
- Rotation cooldown
- New-key access after rotation

Current test result:

```text
11 passed
