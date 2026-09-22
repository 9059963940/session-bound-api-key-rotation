# Session-Bound API Key Rotation via Usage-Pattern Fingerprinting

A local academic security prototype that detects abnormal API-key usage patterns and automatically rotates suspicious API credentials.

The system establishes a behavioral baseline for each API key and evaluates live requests against that baseline. When abnormal behavior produces a sufficiently high risk score, the system revokes the existing API key and generates a new session-bound API key.

> **Note:** This is a research/academic prototype intended for local experimentation and demonstration. It is not a production secrets-management system.

---

## Overview

Traditional API-key rotation is commonly based on fixed schedules or manual intervention.

This project explores a behavior-driven approach in which API-key usage is continuously monitored. The system observes request characteristics, establishes a per-key behavioral baseline, detects deviations using anomaly detection, calculates a risk score, and automatically rotates the affected credential when the configured threshold is exceeded.

### Core Flow

```text
Client
   |
   v
API Gateway
   |
   v
Request / Usage Profiler
   |
   +----------------------+
   |                      |
   v                      v
Behavioral Features   Audit Logging
   |
   v
Isolation Forest
   |
   v
Risk Scoring / Decision Engine
   |
   +----------------------+
   |
   v
Key Vault
   |
   +----------------------+
   |
   v
Revoke Old Key
   |
   v
Generate New Session-Bound Key
