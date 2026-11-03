"""SentinelGate Dashboard - Streamlit UI.

Run: streamlit run dashboard/app.py
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

import streamlit as st

from dashboard.data import (
    get_alert_counts,
    get_alerts,
    get_blocklist,
    get_kpi,
    get_recent_events,
    get_top_attackers,
)

# Page config
st.set_page_config(page_title="SentinelGate Dashboard", page_icon="🛡️", layout="wide")

# Password protection
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "admin")


def check_password():
    """Simple password authentication."""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if st.session_state.authenticated:
        return True

    st.title("🛡️ SentinelGate Dashboard")
    st.write("Enter password to access the dashboard.")

    password = st.text_input("Password", type="password", key="password_input")
    if st.button("Login"):
        if password == DASHBOARD_PASSWORD:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Incorrect password")
    return False


if not check_password():
    st.stop()

# Sidebar
with st.sidebar:
    st.title("🛡️ SentinelGate")
    st.write("**Security Gateway Dashboard**")
    st.divider()

    # Database path
    db_path = st.text_input("Database Path", value="logs/siem.db")
    st.session_state.db_path = db_path

    # Auto-refresh
    auto_refresh = st.checkbox("Auto-refresh (5s)", value=False)
    if auto_refresh:
        st.rerun()

    st.divider()
    if st.button("Logout"):
        st.session_state.authenticated = False
        st.rerun()

# Check database exists
if not os.path.isfile(st.session_state.db_path):
    st.error(f"Database not found: {st.session_state.db_path}")
    st.info("Run the collector first: `python -m siem.collector`")
    st.stop()

# Connect to database
conn = sqlite3.connect(st.session_state.db_path)

# Main content
st.title("📊 Overview")

# KPI row
col1, col2, col3, col4, col5 = st.columns(5)

kpi = get_kpi(conn)

with col1:
    st.metric("Requests/min", f"{kpi['requests_per_min']:.1f}")

with col2:
    st.metric("Blocked", kpi["blocked"])

with col3:
    st.metric("Active Bans", kpi["active_bans"])

with col4:
    st.metric("Open Alerts", kpi["open_alerts"])

with col5:
    st.metric("Avg Risk", f"{kpi['avg_risk']:.1f}")

st.divider()

# Alerts section
st.subheader("🚨 Recent Alerts")

alert_counts = get_alert_counts(conn)
if alert_counts:
    cols = st.columns(4)
    for i, (severity, count) in enumerate(alert_counts.items()):
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
        cols[i % 4].metric(f"{emoji} {severity.title()}", count)

alerts = get_alerts(conn, limit=10)
if alerts:
    alert_data = []
    for alert in alerts:
        alert_data.append(
            {
                "Severity": alert["severity"],
                "Rule": alert["rule"],
                "IP": alert["ip"],
                "Status": alert["status"],
                "Created": alert["created_at"][:19],
            }
        )
    st.dataframe(alert_data, use_container_width=True)
else:
    st.info("No alerts yet. Run the simulator to generate some.")

st.divider()

# Events section
st.subheader("📋 Recent Events")

events = get_recent_events(conn, limit=20)
if events:
    event_data = []
    for ev in events:
        event_data.append(
            {
                "Time": ev["timestamp"][:19],
                "IP": ev["source_ip"],
                "Method": ev["method"],
                "Path": ev["path"][:40],
                "Status": ev["status"],
                "Action": ev["action"],
                "Risk": f"{ev['risk_score']:.1f}",
            }
        )
    st.dataframe(event_data, use_container_width=True, height=400)
else:
    st.info("No events logged yet.")

st.divider()

# Attackers section
st.subheader("🎯 Top Attackers")

attackers = get_top_attackers(conn, limit=10)
if attackers:
    attacker_data = []
    for att in attackers:
        attacker_data.append(
            {
                "IP": att["source_ip"],
                "Requests": att["request_count"],
                "Avg Risk": f"{att['avg_risk']:.1f}",
                "Max Risk": f"{att['max_risk']:.1f}",
            }
        )
    st.dataframe(attacker_data, use_container_width=True)

st.divider()

# Blocklist section
st.subheader("🚫 Blocklist")

blocklist = get_blocklist(conn)
if blocklist:
    blocked_data = []
    for block in blocklist:
        banned_until = datetime.fromtimestamp(block["banned_until"], tz=timezone.utc)
        blocked_data.append(
            {
                "IP": block["ip"],
                "Reason": block["reason"][:50],
                "Banned Until": banned_until.strftime("%Y-%m-%d %H:%M:%S"),
                "Created": block["created_at"][:19],
            }
        )
    st.dataframe(blocked_data, use_container_width=True)
else:
    st.info("No IPs currently blocked.")

# Footer
st.divider()
st.caption("SentinelGate v0.1.0 | MIT License")

conn.close()
