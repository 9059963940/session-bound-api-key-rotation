
import time
import hashlib
import hmac
from datetime import datetime, timezone

from fastapi import (
    FastAPI,
    Header,
    HTTPException,
    Request,
    Depends,
)
from pydantic import BaseModel, Field, field_validator
from .database import (
    init_db,
    get_key,
    insert_request,
    update_request_security,
    all_rotations,
    all_requests,
    all_keys,
)

from .key_vault import KeyVault
from .anomaly import AnomalyDetector
from .rotation import RotationController
from .config import HIGH_RISK_THRESHOLD, SERVICE_NAME, ADMIN_TOKEN


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Session-Bound API Key Rotation",
    description="Behavior-driven API credential security prototype",
    version="1.0.0",
)


# ============================================================
# COMPONENTS
# ============================================================

vault = KeyVault()
detector = AnomalyDetector()
rotator = RotationController()


# ============================================================
# ADMIN AUTHENTICATION
# ============================================================

def require_admin_token(
    x_admin_token: str = Header(default=""),
):
    if not hmac.compare_digest(x_admin_token, ADMIN_TOKEN):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing admin token",
        )


# ============================================================
# REQUEST MODEL
# ============================================================

class KeyIssueRequest(BaseModel):
    service_name: str = Field(
        default=SERVICE_NAME,
        min_length=1,
        max_length=100,
    )

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("service_name must not be blank")

        return value


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup():
    init_db()


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "session-bound-security-gateway",
    }


# ============================================================
# ADMIN: ISSUE KEY
# ============================================================

@app.post(
    "/admin/issue-key",
    dependencies=[Depends(require_admin_token)],
)
def issue_key(body: KeyIssueRequest):
    return vault.generate_session_key(body.service_name)


# ============================================================
# ADMIN: LIST KEYS
# ============================================================

@app.get(
    "/admin/keys",
    dependencies=[Depends(require_admin_token)],
)
def keys():
    return {
        "keys": all_keys(),
    }


# ============================================================
# ADMIN: LIST ROTATIONS
# ============================================================

@app.get(
    "/admin/rotations",
    dependencies=[Depends(require_admin_token)],
)
def rotations():
    return {
        "rotations": all_rotations(),
    }


# ============================================================
# ADMIN: LIST REQUESTS
# ============================================================

@app.get(
    "/admin/requests",
    dependencies=[Depends(require_admin_token)],
)
def requests():
    return {
        "requests": all_requests(),
    }


# ============================================================
# PROTECTED API
# ============================================================

@app.get("/api/secure-data")
def secure_data(
    request: Request,
    x_api_key: str = Header(default=""),
):
    start = time.perf_counter()

    # --------------------------------------------------------
    # 1. API KEY PRESENCE CHECK
    # --------------------------------------------------------

    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing X-API-Key",
        )

    # --------------------------------------------------------
    # 2. API KEY VALIDATION
    # --------------------------------------------------------

    key = get_key(x_api_key)

    if not key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked API key",
        )

    # --------------------------------------------------------
    # 3. CLIENT INFORMATION
    # --------------------------------------------------------

    client_ip = (
        request.client.host
        if request.client
        else "unknown"
    )

    user_agent = request.headers.get(
        "user-agent",
        "unknown",
    )

    fingerprint = hashlib.sha256(
        user_agent.encode()
    ).hexdigest()[:16]

    # --------------------------------------------------------
    # 4. RESPONSE DATA
    # --------------------------------------------------------

    response = {
        "message": "Authorized request",
        "service": key["service_name"],
        "session_id": key["session_id"],
    }

    # --------------------------------------------------------
    # 5. REQUEST METADATA
    # --------------------------------------------------------

    latency_ms = (
        time.perf_counter() - start
    ) * 1000

    body_size = len(
        str(response).encode()
    )

    # --------------------------------------------------------
    # 6. STORE INITIAL REQUEST
    # --------------------------------------------------------

    request_id = insert_request(
        {
            "key_id": key["key_id"],
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "endpoint": "/api/secure-data",
            "method": "GET",
            "payload_size": body_size,
            "client_ip": client_ip,
            "client_fingerprint": fingerprint,
            "status_code": 200,
            "latency_ms": latency_ms,
            "anomaly_score": None,
            "risk_score": None,
            "security_reason": None,
            "rotated": 0,
        }
    )

    # --------------------------------------------------------
    # 7. BEHAVIORAL ANALYSIS
    # --------------------------------------------------------

    result = detector.observe(
        key["key_id"]
    )

    # --------------------------------------------------------
    # 8. CHECK ROTATION CONDITION
    # --------------------------------------------------------

    if result["ready"] and rotator.should_rotate(
        key["key_id"],
        result["risk_score"],
        HIGH_RISK_THRESHOLD,
    ):

        # ----------------------------------------------------
        # 9. ROTATE KEY
        # ----------------------------------------------------

        try:
            new_key = rotator.rotate(
                key,
                result["risk_score"],
            )
        except RuntimeError:
            update_request_security(
                request_id=request_id,
                anomaly_score=result["anomaly_score"],
                risk_score=result["risk_score"],
                security_reason=(
                    "Rotation rejected because the API key "
                    "was already revoked or rotated"
                ),
                rotated=False,
            )

            raise HTTPException(
                status_code=409,
                detail=(
                    "API key rotation conflicted with another request. "
                    "Retry with a current API key."
                ),
            )

        # ----------------------------------------------------
        # 10. UPDATE REQUEST WITH SECURITY RESULTS
        # ----------------------------------------------------

        update_request_security(
            request_id=request_id,
            anomaly_score=result["anomaly_score"],
            risk_score=result["risk_score"],
            security_reason=result["reason"],
            rotated=True,
        )

        # ----------------------------------------------------
        # 11. RETURN ROTATION RESPONSE
        # ----------------------------------------------------

        return {
            **response,
            "security": {
                "rotated": True,
                "risk_score": result["risk_score"],
                "anomaly_score": result["anomaly_score"],
                "reason": result["reason"],
                "new_session_id": new_key["session_id"],
                "new_api_key": new_key["api_key"],
            },
        }

    # --------------------------------------------------------
    # 12. NO ROTATION
    # --------------------------------------------------------

    update_request_security(
        request_id=request_id,
        anomaly_score=result["anomaly_score"],
        risk_score=result["risk_score"],
        security_reason=result["reason"],
        rotated=False,
    )

    # --------------------------------------------------------
    # 13. NORMAL SECURITY RESPONSE
    # --------------------------------------------------------

    return {
        **response,
        "security": {
            "rotated": False,
            "risk_score": result["risk_score"],
            "anomaly_score": result["anomaly_score"],
            "reason": result["reason"],
        },
    }
