# Session-Bound API Key Rotation via Usage-Pattern Fingerprinting

Complete local academic prototype based on the supplied project review documents.

Flow:
Client -> API Gateway -> Usage Profiler -> Isolation Forest -> Risk/Decision Engine
                                  |                         |
                                  v                         v
                              Audit Log                Key Vault
                                                          |
                                                    New session key

Features:
1. API-key issuance.
2. API request logging.
3. Per-key behavioral baseline.
4. Timing/endpoint/payload/client fingerprint features.
5. Isolation Forest anomaly detection.
6. Risk scoring.
7. Automatic key revocation.
8. Session-bound replacement key.
9. Rotation audit log.
10. Streamlit monitoring dashboard.

This is a research/academic prototype, not a production secrets-management system.
