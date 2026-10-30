import streamlit as st
import pandas as pd
import sqlite3
import re
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path("threatforge.db")

st.set_page_config(page_title="ThreatForge Security Suite", page_icon="🛡️", layout="wide")

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            username TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def add_event(ip, username, status, event_time=None):
    event_time = event_time or datetime.now()
    conn = get_conn()
    conn.execute(
        "INSERT INTO login_events (event_time, ip_address, username, status) VALUES (?, ?, ?, ?)",
        (event_time.isoformat(timespec="seconds"), ip, username, status)
    )
    conn.commit()
    conn.close()

def load_events():
    conn = get_conn()
    df = pd.read_sql_query(
        "SELECT id, event_time, ip_address, username, status FROM login_events ORDER BY event_time DESC",
        conn
    )
    conn.close()
    if not df.empty:
        df["event_time"] = pd.to_datetime(df["event_time"])
    return df

def clear_events():
    conn = get_conn()
    conn.execute("DELETE FROM login_events")
    conn.commit()
    conn.close()

def detect_attacks(df, threshold, window_minutes):
    alerts = []
    if df.empty:
        return pd.DataFrame(columns=[
            "IP Address", "Username", "Failed Attempts",
            "First Attempt", "Last Attempt", "Risk"
        ])

    failed = df[df["status"] == "FAILED"].copy()

    for ip in failed["ip_address"].unique():
        ip_failed = failed[failed["ip_address"] == ip].sort_values("event_time")
        times = list(ip_failed["event_time"])

        for current_time in times:
            start = current_time - timedelta(minutes=window_minutes)
            window_df = ip_failed[
                (ip_failed["event_time"] >= start) &
                (ip_failed["event_time"] <= current_time)
            ]

            if len(window_df) >= threshold:
                count = len(window_df)
                risk = "HIGH" if count >= threshold * 2 else "MEDIUM"
                alerts.append({
                    "IP Address": ip,
                    "Username": ", ".join(sorted(window_df["username"].unique())),
                    "Failed Attempts": count,
                    "First Attempt": window_df["event_time"].min(),
                    "Last Attempt": window_df["event_time"].max(),
                    "Risk": risk
                })
                break

    return pd.DataFrame(alerts)

def scan_code_file(path):
    findings = []
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return [{"Severity": "INFO", "Finding": f"Could not read {Path(path).name}: {e}"}]

    checks = [
        ("HIGH", r'password\s*=\s*["\'][^"\']+["\']', "Possible hard-coded password"),
        ("HIGH", r'api[_-]?key\s*=\s*["\'][^"\']+["\']', "Possible hard-coded API key"),
        ("MEDIUM", r'(?i)\bdebug\s*=\s*True\b', "Debug mode appears enabled"),
        ("MEDIUM", r'(?i)\bverify\s*=\s*False\b', "TLS certificate verification appears disabled"),
        ("MEDIUM", r'(?i)\b(?:eval|exec)\s*\(', "Dynamic code execution pattern found"),
        ("LOW", r'(?i)\bTODO\b|\bFIXME\b', "Unresolved TODO/FIXME marker"),
    ]

    for severity, pattern, message in checks:
        if re.search(pattern, text):
            findings.append({
                "Severity": severity,
                "Finding": message,
                "File": Path(path).name
            })
    return findings

def scan_project_code(folder):
    findings = []
    allowed = {".py", ".js", ".ts", ".php", ".java", ".cs", ".json", ".env", ".txt"}
    folder = Path(folder)

    for path in folder.rglob("*"):
        if path.is_file() and path.suffix.lower() in allowed:
            if any(part.lower() in {".git", "venv", ".venv", "node_modules", "__pycache__"} for part in path.parts):
                continue
            findings.extend(scan_code_file(path))
    return findings

def security_controls():
    return [
        {"Control": "Rate limiting", "Status": "Recommended", "Why": "Limits repeated authentication attempts in a short period."},
        {"Control": "Temporary account/IP lockout", "Status": "Recommended", "Why": "Slows repeated automated attempts after the threshold is reached."},
        {"Control": "Multi-factor authentication", "Status": "Recommended", "Why": "Adds another authentication factor if a password is compromised."},
        {"Control": "Strong password policy", "Status": "Recommended", "Why": "Reduces the chance of weak credentials being guessed."},
        {"Control": "Security logging", "Status": "Implemented", "Why": "ThreatForge stores login events in SQLite for investigation."},
        {"Control": "Security alerts", "Status": "Implemented", "Why": "The dashboard flags suspicious failed-login patterns."}
    ]

init_db()

st.title("🛡️ ThreatForge Security Suite")
st.subheader("Brute-Force Detection, Security Checks & Protective Measures")
st.caption("Educational defensive security project. Use only on systems and files you own or are authorized to assess.")

tabs = st.tabs(["🚨 Attack Detection", "🧪 Local Login Lab", "🔍 Security Scanner", "🔐 Credential Check", "🛡️ Protection", "📊 Reports"])

with tabs[0]:
    st.header("Real-Time Brute-Force Detection")
    c1, c2 = st.columns(2)
    with c1:
        threshold = st.slider("Failed-attempt threshold", 2, 20, 5)
    with c2:
        window = st.slider("Detection window (minutes)", 1, 60, 1)

    st.sidebar.header("🧪 Login Simulation")
    ip = st.sidebar.text_input("IP address", "192.168.1.10")
    username = st.sidebar.text_input("Username", "admin")
    status = st.sidebar.selectbox("Login result", ["FAILED", "SUCCESS"])

    if st.sidebar.button("Log Login Attempt", use_container_width=True):
        add_event(ip, username, status)
        st.rerun()

    if st.sidebar.button("Simulate Brute-Force Attack", use_container_width=True):
        now = datetime.now()
        for i in range(threshold + 2):
            add_event(ip, username, "FAILED", now - timedelta(seconds=(threshold + 2 - i) * 5))
        st.rerun()

    if st.sidebar.button("Simulate Normal Login", use_container_width=True):
        add_event(ip, username, "SUCCESS")
        st.rerun()

    if st.sidebar.button("Clear All Events", use_container_width=True):
        clear_events()
        st.rerun()

    df = load_events()
    alerts = detect_attacks(df, threshold, window)

    total = len(df)
    failed_count = int((df["status"] == "FAILED").sum()) if not df.empty else 0
    success_count = int((df["status"] == "SUCCESS").sum()) if not df.empty else 0
    suspicious_ips = alerts["IP Address"].nunique() if not alerts.empty else 0
    high_risk = int((alerts["Risk"] == "HIGH").sum()) if not alerts.empty else 0

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Attempts", total)
    m2.metric("Failed", failed_count)
    m3.metric("Successful", success_count)
    m4.metric("Suspicious IPs", suspicious_ips)
    m5.metric("High Risk Alerts", high_risk)

    if not alerts.empty:
        st.error("🚨 Potential brute-force activity detected!")
        st.dataframe(alerts, use_container_width=True)
    else:
        st.success("✅ No brute-force pattern detected.")

    if not df.empty:
        left, right = st.columns(2)
        with left:
            st.subheader("Login Results")
            st.bar_chart(df["status"].value_counts())
        with right:
            st.subheader("Attempts by IP")
            st.bar_chart(df["ip_address"].value_counts())

        st.subheader("📋 Login Event Log")
        display = df.copy()
        display["event_time"] = display["event_time"].dt.strftime("%Y-%m-%d %H:%M:%S")
        display = display.rename(columns={
            "id": "ID", "event_time": "Time",
            "ip_address": "IP Address",
            "username": "Username", "status": "Status"
        })
        st.dataframe(display, use_container_width=True)

        # Restored CSV export feature.
        csv = display.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Login Log (CSV)",
            data=csv,
            file_name="threatforge_login_log.csv",
            mime="text/csv",
            use_container_width=False
        )
    else:
        st.info("No login events recorded yet.")


with tabs[1]:
    st.header("🧪 Local Login Lab")
    st.write("A safe fake login page for testing ThreatForge in real time. It runs only on your local computer and does not connect to any real account or website.")
    st.warning("Use only the demo credentials shown below. Passwords entered here are NOT stored; only SUCCESS/FAILED login events are logged.")

    demo_user = "student"
    demo_password = "ThreatForge123!"

    st.markdown("### Demo account")
    st.code("Username: student\nDemo password: ThreatForge123!")

    lab_ip = st.text_input("Simulated client IP", "10.0.0.25", key="lab_ip")
    lab_user = st.text_input("Username", "student", key="lab_user")
    lab_password = st.text_input("Password", type="password", key="lab_password")

    if st.button("🔐 Try Login", type="primary"):
        if lab_user == demo_user and lab_password == demo_password:
            add_event(lab_ip, lab_user, "SUCCESS")
            st.success("✅ Demo login successful!")
        else:
            add_event(lab_ip, lab_user, "FAILED")
            st.error("❌ Invalid demo username or password.")

        st.rerun()

    st.markdown("### How to demonstrate brute-force detection")
    st.markdown("""
    1. Keep the **Simulated client IP** the same.
    2. Enter the username `student`.
    3. Enter different wrong passwords and click **Try Login** several times.
    4. After the configured threshold is reached, switch to **🚨 Attack Detection**.
    5. You should see the suspicious IP and brute-force alert in the dashboard.
    6. Finally, enter the demo password to show a successful login event.

    The password itself is never written to the SQLite database or CSV export.
    """)


with tabs[2]:
    st.header("🔍 Local Security / Bug Scanner")
    st.write("Defensive static checks for code you own. This is an educational heuristic scanner, not a professional vulnerability scanner.")
    scan_folder = st.text_input("Project folder to scan", str(Path.cwd()))

    if st.button("Run Local Security Scan"):
        folder = Path(scan_folder)
        if not folder.exists() or not folder.is_dir():
            st.error("That folder does not exist.")
        else:
            findings = scan_project_code(folder)
            if findings:
                scan_df = pd.DataFrame(findings)
                order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
                scan_df["_order"] = scan_df["Severity"].map(order).fillna(9)
                scan_df = scan_df.sort_values("_order").drop(columns="_order")
                s1, s2, s3 = st.columns(3)
                s1.metric("High", int((scan_df["Severity"] == "HIGH").sum()))
                s2.metric("Medium", int((scan_df["Severity"] == "MEDIUM").sum()))
                s3.metric("Low", int((scan_df["Severity"] == "LOW").sum()))
                st.dataframe(scan_df, use_container_width=True)
            else:
                st.success("✅ No issues were found by these basic heuristic checks.")

with tabs[3]:
    st.header("🔐 Credential Security Check")
    st.write("Checks password strength locally. Do not enter a real password.")
    password = st.text_input("Enter a test password", type="password")

    if password:
        score = 0
        tips = []
        if len(password) >= 12: score += 2
        elif len(password) >= 8: score += 1
        else: tips.append("Use at least 12 characters.")
        if re.search(r"[A-Z]", password): score += 1
        else: tips.append("Add an uppercase letter.")
        if re.search(r"[a-z]", password): score += 1
        else: tips.append("Add a lowercase letter.")
        if re.search(r"\d", password): score += 1
        else: tips.append("Add a number.")
        if re.search(r"[^A-Za-z0-9]", password): score += 1
        else: tips.append("Add a special character.")
        if password.lower() in {"password", "123456", "12345678", "qwerty", "admin", "letmein"}:
            score = 0
            tips.append("Avoid common passwords.")

        if score >= 6: st.success("Strong test password")
        elif score >= 4: st.warning("Moderate test password")
        else: st.error("Weak test password")
        st.progress(min(score / 6, 1.0))
        for tip in tips:
            st.write("• " + tip)

    st.info("For real breach monitoring, use an authorized breach-notification service or your organization's identity provider. Do not upload real passwords or secrets to this demo.")

with tabs[4]:
    st.header("🛡️ Protective Measures")
    st.dataframe(pd.DataFrame(security_controls()), use_container_width=True)
    st.subheader("Recommended response workflow")
    st.markdown("""
    **1. Detect** → Identify repeated failed attempts.  
    **2. Alert** → Notify the administrator.  
    **3. Slow down** → Apply rate limiting or temporary lockout.  
    **4. Verify** → Require stronger authentication such as MFA.  
    **5. Investigate** → Review stored security logs.  
    **6. Recover** → Reset compromised credentials and document the incident.
    """)

with tabs[5]:
    st.header("📊 Security Report")
    df = load_events()
    alerts = detect_attacks(df, 5, 1)

    report = "\n".join([
        "THREATFORGE SECURITY ASSESSMENT",
        "=" * 36,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "LOGIN MONITORING",
        f"Total events: {len(df)}",
        f"Failed events: {int((df['status'] == 'FAILED').sum()) if not df.empty else 0}",
        f"Successful events: {int((df['status'] == 'SUCCESS').sum()) if not df.empty else 0}",
        f"Suspicious IPs: {alerts['IP Address'].nunique() if not alerts.empty else 0}",
        "",
        "PROTECTIVE MEASURES",
        "Rate limiting: Recommended",
        "Temporary lockout: Recommended",
        "MFA: Recommended",
        "Strong password policy: Recommended",
        "Security logging: Implemented",
        "Security alerts: Implemented",
    ])
    st.text(report)
    st.download_button("⬇️ Download Security Report", report, "threatforge_security_report.txt", "text/plain")

    st.subheader("Project scope")
    st.write("ThreatForge is an educational defensive prototype. Its detection rules and static checks should not be presented as a replacement for a professional security audit.")
