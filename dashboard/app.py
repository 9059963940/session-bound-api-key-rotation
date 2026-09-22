import time
from datetime import datetime

import pandas as pd
import requests
import streamlit as st


# ============================================================
# CONFIGURATION
# ============================================================

BACKEND_URL = "http://127.0.0.1:8000"

HEALTH_URL = f"{BACKEND_URL}/health"
KEYS_URL = f"{BACKEND_URL}/admin/keys"
REQUESTS_URL = f"{BACKEND_URL}/admin/requests"
ROTATIONS_URL = f"{BACKEND_URL}/admin/rotations"

HIGH_RISK_THRESHOLD = 0.65


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Session-Bound API Key Security",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 2.3rem;
        font-weight: 750;
        margin-bottom: 0.15rem;
    }

    .subtitle {
        font-size: 1rem;
        color: #666666;
        margin-bottom: 1.5rem;
    }

    .section-title {
        font-size: 1.35rem;
        font-weight: 700;
        margin-top: 1.6rem;
        margin-bottom: 0.8rem;
    }

    .security-card {
        padding: 18px;
        border-radius: 12px;
        border: 1px solid #dddddd;
        background-color: #fafafa;
        text-align: center;
    }

    .security-card-title {
        font-size: 0.9rem;
        color: #666666;
        margin-bottom: 5px;
    }

    .security-card-value {
        font-size: 1.35rem;
        font-weight: 700;
    }

    .event-card {
        padding: 18px;
        border-radius: 12px;
        border: 1px solid #dddddd;
        background-color: #fafafa;
        margin-bottom: 10px;
    }

    .small-text {
        font-size: 0.85rem;
        color: #666666;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def fetch_json(url):
    """Fetch JSON data from the FastAPI backend."""

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.json()

    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.RequestException,
        ValueError,
    ):
        return None


def safe_list(data, key):
    """Safely extract a list from an API response."""

    if not isinstance(data, dict):
        return []

    value = data.get(key, [])

    if isinstance(value, list):
        return value

    return []


def format_timestamp(value):
    """Convert ISO timestamp to readable timestamp."""

    if not value:
        return "—"

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        return parsed.strftime("%Y-%m-%d %H:%M:%S")

    except (ValueError, TypeError):
        return str(value)


def shorten(value, length=16):
    """Shorten long IDs for dashboard display."""

    if value is None:
        return "—"

    value = str(value)

    if len(value) <= length:
        return value

    return value[:length] + "..."


def numeric_series(df, column):
    """Convert a dataframe column safely to numeric."""

    if column not in df.columns:
        return pd.Series(dtype=float)

    return pd.to_numeric(
        df[column],
        errors="coerce",
    )


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## 🔐 Security Monitor")

    st.markdown(
        """
        **Session-Bound API Key Rotation**

        Monitoring:

        - API key activity
        - Request logging
        - Behavioral anomalies
        - Risk scores
        - Automatic rotation
        - Key revocation
        - Rotation auditing
        """
    )

    st.divider()

    refresh_seconds = st.number_input(
        "Refresh interval (seconds)",
        min_value=5,
        max_value=300,
        value=10,
        step=5,
    )

    auto_refresh = st.checkbox(
        "Auto refresh",
        value=False,
    )

    st.divider()

    st.caption(
        f"Backend: {BACKEND_URL}"
    )

    if st.button(
        "🔄 Refresh now",
        use_container_width=True,
    ):
        st.rerun()


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">'
    'Session-Bound API Key Security Dashboard'
    '</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="subtitle">'
    'Behavioral Anomaly Detection & '
    'Automatic API Credential Rotation'
    '</div>',
    unsafe_allow_html=True,
)


# ============================================================
# FETCH BACKEND DATA
# ============================================================

health_data = fetch_json(HEALTH_URL)
keys_data = fetch_json(KEYS_URL)
requests_data = fetch_json(REQUESTS_URL)
rotations_data = fetch_json(ROTATIONS_URL)


# ============================================================
# BACKEND CONNECTION
# ============================================================

if health_data is None:

    st.error(
        "Cannot connect to the FastAPI backend."
    )

    st.code(
        "uvicorn app.main:app --reload "
        "--host 127.0.0.1 --port 8000"
    )

    st.stop()

else:

    st.success(
        "FastAPI backend is connected and running."
    )


# ============================================================
# EXTRACT DATA
# ============================================================

keys = safe_list(
    keys_data,
    "keys",
)

request_records = safe_list(
    requests_data,
    "requests",
)

rotation_records = safe_list(
    rotations_data,
    "rotations",
)


# ============================================================
# DATAFRAMES
# ============================================================

keys_df = pd.DataFrame(keys)

requests_df = pd.DataFrame(
    request_records
)

rotations_df = pd.DataFrame(
    rotation_records
)


# ============================================================
# SUMMARY VALUES
# ============================================================

total_keys = len(keys)

active_keys = sum(
    1
    for key in keys
    if key.get("active") in (1, True)
)

revoked_keys = sum(
    1
    for key in keys
    if key.get("active") in (0, False)
)

total_requests = len(request_records)

total_rotations = len(
    rotation_records
)


# ============================================================
# REQUEST STATISTICS
# ============================================================

successful_requests = 0
failed_requests = 0
max_risk = 0.0
max_anomaly = 0.0

if not requests_df.empty:

    if "status_code" in requests_df.columns:

        status_values = pd.to_numeric(
            requests_df["status_code"],
            errors="coerce",
        )

        successful_requests = int(
            (status_values == 200).sum()
        )

        failed_requests = int(
            (status_values >= 400).sum()
        )

    if "risk_score" in requests_df.columns:

        risk_values = numeric_series(
            requests_df,
            "risk_score",
        )

        if risk_values.notna().any():

            max_risk = float(
                risk_values.max()
            )

    if "anomaly_score" in requests_df.columns:

        anomaly_values = numeric_series(
            requests_df,
            "anomaly_score",
        )

        if anomaly_values.notna().any():

            max_anomaly = float(
                anomaly_values.max()
            )


# ============================================================
# SYSTEM OVERVIEW
# ============================================================

st.markdown(
    '<div class="section-title">'
    '📊 System Overview'
    '</div>',
    unsafe_allow_html=True,
)

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Total API Keys",
        total_keys,
    )

with col2:
    st.metric(
        "Active Keys",
        active_keys,
    )

with col3:
    st.metric(
        "Logged Requests",
        total_requests,
    )

with col4:
    st.metric(
        "Rotations",
        total_rotations,
    )


# ============================================================
# SECURITY HEALTH
# ============================================================

st.markdown(
    '<div class="section-title">'
    '🛡️ Security Health'
    '</div>',
    unsafe_allow_html=True,
)

health_col1, health_col2, health_col3, health_col4 = (
    st.columns(4)
)


with health_col1:

    if active_keys > 0:

        st.success(
            "ACTIVE CREDENTIAL\n\n"
            "A valid credential is available."
        )

    else:

        st.warning(
            "NO ACTIVE CREDENTIAL\n\n"
            "No active API key detected."
        )


with health_col2:

    if total_requests > 0:

        st.success(
            "MONITORING ACTIVE\n\n"
            f"{total_requests} requests logged."
        )

    else:

        st.warning(
            "NO REQUESTS\n\n"
            "Waiting for API traffic."
        )


with health_col3:

    if total_rotations > 0:

        st.info(
            "ROTATION ACTIVE\n\n"
            f"{total_rotations} rotation event(s)."
        )

    else:

        st.info(
            "ROTATION READY\n\n"
            "No rotation events yet."
        )


with health_col4:

    if max_risk >= HIGH_RISK_THRESHOLD:

        st.error(
            "HIGH RISK DETECTED\n\n"
            f"Maximum risk: {max_risk:.4f}"
        )

    else:

        st.success(
            "RISK WITHIN RANGE\n\n"
            f"Maximum risk: {max_risk:.4f}"
        )


# ============================================================
# API KEY STATUS
# ============================================================

st.markdown(
    '<div class="section-title">'
    '🔑 API Key Status'
    '</div>',
    unsafe_allow_html=True,
)

if keys:

    display_keys = []

    for key in keys:

        active = (
            key.get("active")
            in (1, True)
        )

        display_keys.append(
            {
                "Key ID": shorten(
                    key.get("key_id")
                ),
                "Service": key.get(
                    "service_name",
                    "—",
                ),
                "Session ID": shorten(
                    key.get("session_id")
                ),
                "Created": format_timestamp(
                    key.get("created_at")
                ),
                "Revoked": (
                    format_timestamp(
                        key.get("revoked_at")
                    )
                    if key.get("revoked_at")
                    else "—"
                ),
                "Status": (
                    "ACTIVE"
                    if active
                    else "REVOKED"
                ),
            }
        )

    keys_display_df = pd.DataFrame(
        display_keys
    )

    st.dataframe(
        keys_display_df,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info(
        "No API keys have been created yet."
    )


# ============================================================
# REQUEST & RISK ANALYSIS
# ============================================================

st.markdown(
    '<div class="section-title">'
    '📈 Request & Risk Analysis'
    '</div>',
    unsafe_allow_html=True,
)

if requests_df.empty:

    st.info(
        "No request records are available yet."
    )

else:

    if "timestamp" in requests_df.columns:

        requests_df["timestamp_parsed"] = (
            pd.to_datetime(
                requests_df["timestamp"],
                errors="coerce",
            )
        )

    risk_values = numeric_series(
        requests_df,
        "risk_score",
    )

    anomaly_values = numeric_series(
        requests_df,
        "anomaly_score",
    )

    analysis_col1, analysis_col2, analysis_col3, analysis_col4 = (
        st.columns(4)
    )

    with analysis_col1:

        st.metric(
            "Successful Requests",
            successful_requests,
        )

    with analysis_col2:

        st.metric(
            "Failed Requests",
            failed_requests,
        )

    with analysis_col3:

        st.metric(
            "Maximum Risk",
            f"{max_risk:.4f}",
        )

    with analysis_col4:

        st.metric(
            "Maximum Anomaly",
            f"{max_anomaly:.4f}",
        )


    # --------------------------------------------------------
    # Risk chart
    # --------------------------------------------------------

    if (
        not risk_values.empty
        and risk_values.notna().any()
    ):

        risk_chart_df = requests_df.copy()

        risk_chart_df["Risk Score"] = (
            pd.to_numeric(
                risk_chart_df["risk_score"],
                errors="coerce",
            )
        )

        risk_chart_df = (
            risk_chart_df.dropna(
                subset=["Risk Score"]
            )
        )

        if not risk_chart_df.empty:

            if "timestamp_parsed" in risk_chart_df.columns:

                risk_chart_df = (
                    risk_chart_df.sort_values(
                        "timestamp_parsed"
                    )
                )

            st.markdown(
                "#### Risk Score Over Requests"
            )

            st.line_chart(
                risk_chart_df[
                    ["Risk Score"]
                ],
                use_container_width=True,
            )


    # --------------------------------------------------------
    # Anomaly chart
    # --------------------------------------------------------

    if (
        not anomaly_values.empty
        and anomaly_values.notna().any()
    ):

        anomaly_chart_df = requests_df.copy()

        anomaly_chart_df["Anomaly Score"] = (
            pd.to_numeric(
                anomaly_chart_df[
                    "anomaly_score"
                ],
                errors="coerce",
            )
        )

        anomaly_chart_df = (
            anomaly_chart_df.dropna(
                subset=["Anomaly Score"]
            )
        )

        if not anomaly_chart_df.empty:

            if "timestamp_parsed" in anomaly_chart_df.columns:

                anomaly_chart_df = (
                    anomaly_chart_df.sort_values(
                        "timestamp_parsed"
                    )
                )

            st.markdown(
                "#### Anomaly Score Over Requests"
            )

            st.line_chart(
                anomaly_chart_df[
                    ["Anomaly Score"]
                ],
                use_container_width=True,
            )


# ============================================================
# HIGH-RISK EVENTS
# ============================================================

st.markdown(
    '<div class="section-title">'
    '🚨 High-Risk Events'
    '</div>',
    unsafe_allow_html=True,
)

if requests_df.empty:

    st.info(
        "No requests available for risk analysis."
    )

elif "risk_score" not in requests_df.columns:

    st.info(
        "Risk-score data is not available."
    )

else:

    high_risk_df = requests_df.copy()

    high_risk_df["risk_numeric"] = (
        pd.to_numeric(
            high_risk_df["risk_score"],
            errors="coerce",
        )
    )

    high_risk_df = high_risk_df[
        high_risk_df["risk_numeric"]
        >= HIGH_RISK_THRESHOLD
    ]

    if high_risk_df.empty:

        st.success(
            "No high-risk requests detected."
        )

    else:

        high_risk_display = []

        for _, row in high_risk_df.tail(20).iloc[::-1].iterrows():

            high_risk_display.append(
                {
                    "Timestamp": format_timestamp(
                        row.get("timestamp")
                    ),
                    "Risk Score": round(
                        float(
                            row.get(
                                "risk_numeric",
                                0,
                            )
                        ),
                        4,
                    ),
                    "Anomaly Score": round(
                        float(
                            row.get(
                                "anomaly_score",
                                0,
                            )
                            or 0
                        ),
                        4,
                    ),
                    "Status": row.get(
                        "status_code",
                        "—",
                    ),
                    "Reason": row.get(
                        "security_reason",
                        "—",
                    ),
                    "Rotated": (
                        "YES"
                        if row.get(
                            "rotated"
                        ) in (1, True)
                        else "NO"
                    ),
                }
            )

        high_risk_display_df = pd.DataFrame(
            high_risk_display
        )

        st.dataframe(
            high_risk_display_df,
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# ROTATION EVENTS
# ============================================================

st.markdown(
    '<div class="section-title">'
    '🔄 Automatic Rotation Events'
    '</div>',
    unsafe_allow_html=True,
)

if rotation_records:

    rotation_display = []

    for rotation in rotation_records:

        rotation_display.append(
            {
                "ID": rotation.get(
                    "id",
                    "—",
                ),
                "Old Key": shorten(
                    rotation.get(
                        "old_key_id"
                    )
                ),
                "New Key": shorten(
                    rotation.get(
                        "new_key_id"
                    )
                ),
                "Session": shorten(
                    rotation.get(
                        "session_id"
                    )
                ),
                "Reason": rotation.get(
                    "reason",
                    "—",
                ),
                "Risk Score": rotation.get(
                    "risk_score",
                    "—",
                ),
                "Created": format_timestamp(
                    rotation.get(
                        "created_at"
                    )
                ),
            }
        )

    rotation_display_df = pd.DataFrame(
        rotation_display
    )

    st.dataframe(
        rotation_display_df,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info(
        "No automatic key rotations have occurred yet."
    )


# ============================================================
# LATEST ROTATION EVENT
# ============================================================

if rotation_records:

    latest_rotation = rotation_records[0]

    st.markdown(
        '<div class="section-title">'
        '⚡ Latest Security Event'
        '</div>',
        unsafe_allow_html=True,
    )

    event_col1, event_col2, event_col3, event_col4 = (
        st.columns(4)
    )

    with event_col1:

        st.metric(
            "Risk Score",
            str(
                latest_rotation.get(
                    "risk_score",
                    "—",
                )
            ),
        )

    with event_col2:

        st.metric(
            "Old Key",
            shorten(
                latest_rotation.get(
                    "old_key_id"
                )
            ),
        )

    with event_col3:

        st.metric(
            "New Key",
            shorten(
                latest_rotation.get(
                    "new_key_id"
                )
            ),
        )

    with event_col4:

        st.metric(
            "Action",
            "ROTATED",
        )

    st.info(
        "Reason: "
        + str(
            latest_rotation.get(
                "reason",
                "—",
            )
        )
    )


# ============================================================
# RECENT API REQUESTS
# ============================================================

st.markdown(
    '<div class="section-title">'
    '📝 Recent API Requests'
    '</div>',
    unsafe_allow_html=True,
)

if request_records:

    recent_requests = request_records[-20:]

    recent_display = []

    for request_record in reversed(
        recent_requests
    ):

        risk = request_record.get(
            "risk_score"
        )

        anomaly = request_record.get(
            "anomaly_score"
        )

        recent_display.append(
            {
                "Timestamp": format_timestamp(
                    request_record.get(
                        "timestamp"
                    )
                ),
                "Endpoint": request_record.get(
                    "endpoint",
                    "—",
                ),
                "Method": request_record.get(
                    "method",
                    "—",
                ),
                "Status": request_record.get(
                    "status_code",
                    "—",
                ),
                "Risk": (
                    round(
                        float(risk),
                        4,
                    )
                    if risk is not None
                    else "—"
                ),
                "Anomaly": (
                    round(
                        float(anomaly),
                        4,
                    )
                    if anomaly is not None
                    else "—"
                ),
                "Rotated": (
                    "YES"
                    if request_record.get(
                        "rotated"
                    ) in (1, True)
                    else "NO"
                ),
                "Key ID": shorten(
                    request_record.get(
                        "key_id"
                    )
                ),
                "Client": shorten(
                    request_record.get(
                        "client_fingerprint"
                    )
                ),
            }
        )

    recent_df = pd.DataFrame(
        recent_display
    )

    st.dataframe(
        recent_df,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info(
        "No API requests have been logged yet."
    )


# ============================================================
# PROJECT SECURITY STATUS
# ============================================================

st.markdown(
    '<div class="section-title">'
    '🔐 Project Security Status'
    '</div>',
    unsafe_allow_html=True,
)

status_col1, status_col2, status_col3 = (
    st.columns(3)
)

with status_col1:

    if active_keys > 0:

        st.success(
            "ACTIVE CREDENTIAL AVAILABLE"
        )

    else:

        st.warning(
            "NO ACTIVE CREDENTIAL"
        )


with status_col2:

    if total_rotations > 0:

        st.success(
            "AUTOMATIC ROTATION VERIFIED"
        )

    else:

        st.info(
            "WAITING FOR ROTATION EVENT"
        )


with status_col3:

    if total_requests > 0:

        st.success(
            "REQUEST MONITORING ACTIVE"
        )

    else:

        st.warning(
            "WAITING FOR API TRAFFIC"
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Session-Bound API Key Rotation | "
    "Behavior-driven API credential security prototype"
)


# ============================================================
# AUTO REFRESH
# ============================================================

if auto_refresh:

    time.sleep(
        refresh_seconds
    )

    st.rerun()