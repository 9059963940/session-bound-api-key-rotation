from datetime import datetime
import hashlib


def endpoint_id(endpoint: str) -> int:
    known = {
        "/api/secure-data": 1,
        "/api/profile": 2,
        "/api/orders": 3,
        "/api/health": 4,
        "/api/admin": 5,
        "/api/export": 6,
    }

    return known.get(endpoint, 99)


def stable_hash(value: str) -> int:
    """
    Convert a string into a deterministic numeric value.

    Python's built-in hash() can change between processes,
    so SHA-256 is used for reproducible feature values.
    """
    digest = hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()

    return int(digest[:8], 16) % 1000


def parse_ts(ts):
    return datetime.fromisoformat(
        ts.replace("Z", "+00:00")
    )


def extract_features(requests):
    result = []
    previous = None

    for r in requests:

        current = parse_ts(
            r["timestamp"]
        )

        delta = (
            1.0
            if previous is None
            else max(
                (current - previous).total_seconds(),
                0.001
            )
        )

        previous = current

        result.append(
            [
                delta,
                endpoint_id(
                    r["endpoint"]
                ),
                float(
                    r["payload_size"]
                ),
                1.0
                if r["method"] == "POST"
                else 0.0,
                stable_hash(
                    r["client_fingerprint"]
                ),
                stable_hash(
                    r["client_ip"]
                ),
            ]
        )

    return result