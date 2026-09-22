# Session-Bound API Key Rotation via Usage-Pattern Fingerprinting

A local academic security prototype for detecting abnormal API-key usage patterns and automatically rotating suspicious API credentials.

The system establishes a behavioral baseline for API keys and evaluates live API requests against that baseline. When abnormal behavior produces a sufficiently high risk score, the system automatically revokes the existing API key and generates a new session-bound API key.

> **Note:** This is a research/academic prototype intended for local experimentation and demonstration. It is not a production secrets-management system.

---

## Overview

Traditional API-key rotation is often based on fixed schedules or manual intervention.

This project explores a behavior-driven approach where API-key usage is monitored continuously. The system observes request characteristics, establishes a per-key behavioral baseline, detects deviations using anomaly detection, calculates a risk score, and can automatically rotate the affected credential.

### Core Flow

```text
Client
   |
   v
FastAPI Backend
   |
   v
API Request Logging
   |
   v
Feature Extraction
   |
   +-------------------------------+
   |                               |
   v                               v
Timing / Endpoint            Client Fingerprint
Payload / Method             Client IP
   |                               |
   +---------------+---------------+
                   |
                   v
          Behavioral Baseline
                   |
                   v
          Isolation Forest
                   |
                   v
         Anomaly / Risk Score
                   |
                   v
          Rotation Decision
                   |
        +----------+----------+
        |                     |
        v                     v
 Normal Behavior        High-Risk Behavior
        |                     |
        v                     v
  Allow Request         Revoke Old Key
                              |
                              v
                       Generate New Key
                              |
                              v
                       New Session ID
                              |
                              v
                       Audit Rotation
