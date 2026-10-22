import numpy as np
from sklearn.ensemble import IsolationForest

from .features import extract_features
from .database import recent_requests
from .config import BASELINE_REQUESTS


class AnomalyDetector:

    def observe(self, key_id):

        requests = recent_requests(key_id, 300)

        # ---------------------------------------------------------
        # PHASE 1: LEARN THE COMPLETE BASELINE
        # ---------------------------------------------------------
        #
        # We need a COMPLETE baseline before running anomaly
        # detection.
        #
        # If BASELINE_REQUESTS = 30:
        #
        # Request 1  -> 1/30
        # ...
        # Request 29 -> 29/30
        # Request 30 -> 30/30
        #
        # Detection starts only from request 31.
        # ---------------------------------------------------------

        if len(requests) <= BASELINE_REQUESTS:

            return {
                "ready": False,
                "anomaly_score": 0.0,
                "risk_score": 0.0,
                "reason": (
                    f"Learning baseline: "
                    f"{len(requests)}/{BASELINE_REQUESTS} requests"
                )
            }

        # ---------------------------------------------------------
        # PHASE 2: SPLIT BASELINE AND CURRENT REQUEST
        # ---------------------------------------------------------

        baseline = requests[:-1]
        current = requests[-1:]

        if len(baseline) < BASELINE_REQUESTS:

            return {
                "ready": False,
                "anomaly_score": 0.0,
                "risk_score": 0.0,
                "reason": "Not enough baseline samples"
            }

        # ---------------------------------------------------------
        # PHASE 3: EXTRACT FEATURES
        # ---------------------------------------------------------

        all_features = np.array(
            extract_features(requests),
            dtype=float
        )

        X = all_features[:-1]
        current_X = all_features[-1:]

        # ---------------------------------------------------------
        # PHASE 4: TRAIN ISOLATION FOREST
        # ---------------------------------------------------------

        model = IsolationForest(
            n_estimators=200,
            contamination=0.10,
            random_state=42
        )

        model.fit(X)

        raw_score = float(
            model.decision_function(current_X)[0]
        )

        # Convert Isolation Forest score into
        # a 0-1 anomaly score.
        anomaly_score = float(
            np.clip(
                0.5 - raw_score,
                0.0,
                1.0
            )
        )

        # ---------------------------------------------------------
        # PHASE 5: ADD BEHAVIORAL SIGNALS
        # ---------------------------------------------------------

        known_endpoints = {
            r["endpoint"]
            for r in baseline
        }

        unfamiliar_endpoint = (
            current[0]["endpoint"]
            not in known_endpoints
        )

        known_fingerprints = {
            r["client_fingerprint"]
            for r in baseline
        }

        unfamiliar_fingerprint = (
            current[0]["client_fingerprint"]
            not in known_fingerprints
        )

        risk = anomaly_score

        # New/unfamiliar endpoint
        if unfamiliar_endpoint:
            risk = min(1.0, risk + 0.20)

        # A client fingerprint not seen in this key's baseline
        if unfamiliar_fingerprint:
            risk = min(1.0, risk + 0.45)

        # Very large payload
        if current[0]["payload_size"] > 10000:
            risk = min(1.0, risk + 0.10)

        # ---------------------------------------------------------
        # PHASE 6: RETURN SECURITY RESULT
        # ---------------------------------------------------------

        return {
            "ready": True,
            "anomaly_score": round(
                anomaly_score,
                4
            ),
            "risk_score": round(
                risk,
                4
            ),
            "unfamiliar_endpoint": unfamiliar_endpoint,
            "unfamiliar_fingerprint": unfamiliar_fingerprint,
            "reason": (
                "Live behavior compared against "
                "the per-key baseline"
            )
        }