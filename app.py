
import streamlit as st
import pandas as pd
from transformers import pipeline
import plotly.express as px
import requests
import base64
from datetime import datetime
import re
import textwrap

# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="PhishLog Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# =====================================================
# LOAD MODEL
# =====================================================

@st.cache_resource
def load_model():

    classifier = pipeline(
        "text-classification",
        model="ealvaradob/bert-finetuned-phishing"
    )

    return classifier


classifier = load_model()

# =====================================================
# VIRUSTOTAL API
# =====================================================

VT_API_KEY = st.secrets["VT_API_KEY"]

# =====================================================
# VIRUSTOTAL URL CHECKER
# =====================================================

def check_url_virustotal(url):

    headers = {
        "x-apikey": VT_API_KEY
    }

    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    response = requests.get(
        vt_url,
        headers=headers
    )

    if response.status_code == 200:

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats["malicious"]
        suspicious = stats["suspicious"]

        return malicious, suspicious

    else:

        return None, None


# =====================================================
# INPUT TYPE CHECKER
# =====================================================

def is_url_input(text):

    url_pattern = re.compile(
        r"^(https?://)?(www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}.*$"
    )

    return bool(url_pattern.match(text.strip()))

# =====================================================
# LOAD DATA
# =====================================================

@st.cache_data
def load_data():

    df = pd.read_csv("final_cleaned_v3.csv")

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    return df


df = load_data()

# =====================================================
# CUSTOM CSS
# =====================================================

st.markdown("""
<style>

.stApp {
    background: #071B34;
    color: white;
    font-family: 'Segoe UI', sans-serif;
}

section[data-testid="stSidebar"] {
    background-color: #0B2447;
    border-right: 1px solid rgba(255,255,255,0.08);
}

/* =================================================
SIDEBAR NAVIGATION
================================================= */

section[data-testid="stSidebar"] .stRadio {
    width: 100% !important;
}

section[data-testid="stSidebar"] [role="radiogroup"] {
    width: 100% !important;
    gap: 12px !important;
}

section[data-testid="stSidebar"] .stRadio label {
    width: 100% !important;
    min-height: 62px !important;
    display: flex !important;
    align-items: center !important;
    padding: 14px 18px !important;
    margin-bottom: 10px !important;
    border-radius: 14px !important;
    transition: 0.2s ease-in-out !important;
    white-space: normal !important;
}

section[data-testid="stSidebar"] .stRadio label p {
    font-size: clamp(14px, 1.1vw, 20px) !important;
    font-weight: 600 !important;
    line-height: 1.3 !important;
    white-space: normal !important;
    word-break: normal !important;
}

section[data-testid="stSidebar"] .stRadio label:hover {
    background-color: rgba(0,194,255,0.15) !important;
    border: 1px solid rgba(0,194,255,0.25) !important;
    cursor: pointer !important;
}

/* =================================================
MAIN CONTAINER
================================================= */

.block-container {
    padding-top: 1rem;
    padding-left: 2rem;
    padding-right: 2rem;
}

/* =================================================
KPI CARDS
================================================= */

[data-testid="stMetric"] {
    background: #0D2347;
    padding: 18px;
    border-radius: 18px;
    border: 1px solid rgba(255,255,255,0.08);
    border-left: 5px solid #00C2FF;
}

/* =================================================
BUTTONS
================================================= */

div.stButton > button {
    background: linear-gradient(90deg, #00C2FF, #007BFF);
    color: white;
    border: none;
    border-radius: 10px;
    padding: 10px 18px;
    font-weight: bold;
}

/* =================================================
TEXT AREA
================================================= */

textarea {
    background-color: #0D2347 !important;
    color: white !important;
    border-radius: 12px !important;
    border: 1px solid #1E4E8C !important;
}

/* =================================================
DATAFRAME
================================================= */

[data-testid="stDataFrame"] {
    border-radius: 15px;
    overflow: hidden;
}

/* =================================================
HEADINGS
================================================= */

h1, h2, h3 {
    color: white !important;
}

/* =================================================
SIDEBAR RESPONSIVE FIX
================================================= */

section[data-testid="stSidebar"] img {
    width: 80% !important;
    max-width: none !important;
    min-width: 120px !important;
    display: block;
    margin-left: auto;
    margin-right: auto;
}

section[data-testid="stSidebar"] .stMarkdown {
    width: 100% !important;
}

section[data-testid="stSidebar"] .welcome-text,
section[data-testid="stSidebar"] .logo-text,
section[data-testid="stSidebar"] .tagline-text {
    width: 100% !important;
    text-align: center !important;
}

/* =================================================
MOBILE RESPONSIVE FIX
================================================= */

@media (max-width: 768px) {

    .block-container {
        padding-left: 1rem !important;
        padding-right: 1rem !important;
    }

    h1 {
        font-size: 32px !important;
    }

    h2 {
        font-size: 26px !important;
    }

    h3 {
        font-size: 22px !important;
    }

    p, li, .info-text, .phish-text {
        word-wrap: break-word !important;
        overflow-wrap: break-word !important;
    }

    a {
        word-break: break-word !important;
        overflow-wrap: anywhere !important;
    }

    [data-testid="stHorizontalBlock"] {
        flex-direction: column !important;
    }

    [data-testid="column"] {
        width: 100% !important;
        min-width: 100% !important;
        flex: 1 1 100% !important;
    }

    .element-container {
        width: 100% !important;
    }

    section[data-testid="stSidebar"] img {
        width: 85% !important;
        max-width: 160px !important;
    }

    .logo-text {
        font-size: 34px !important;
    }

    .welcome-text {
        font-size: 15px !important;
    }

    .tagline-text {
        font-size: 12px !important;
    }

    [data-testid="stMetric"] {
        margin-bottom: 15px !important;
    }

    .info-box,
    .phish-box {
        height: auto !important;
        min-height: auto !important;
    }
}

</style>
""", unsafe_allow_html=True)

# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.image("logo.png", use_container_width=True)

st.sidebar.markdown(
    """
    <style>

    .welcome-text {
        color: white;
        font-size: 18px;
        font-weight: 700;
        letter-spacing: 1px;
        margin-bottom: -8px;
        text-align: center;
    }

    .logo-text {
        font-size: 42px;
        font-family: cursive;
        font-weight: bold;
        text-align: center;

        background: linear-gradient(
            90deg,
            #00C2FF,
            #7B68EE,
            #C800FF
        );

        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;

        text-shadow:
            0px 0px 8px rgba(0,194,255,0.4),
            0px 0px 14px rgba(200,0,255,0.3);

        margin-bottom: 5px;
    }

    .tagline-text {
        color: #7FDBFF;
        font-size: 14px;
        text-align: center;
        margin-bottom: 10px;
    }

    </style>

    <div class="welcome-text">
        WELCOME TO
    </div>

    <div class="logo-text">
        PhishLog!
    </div>

    <div class="tagline-text">
        Gen-AI Enhanced Monitoring
    </div>

    """,
    unsafe_allow_html=True
)

menu = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Scan URL / Text",
        "User Manual",
        "About",
        "Phishing Related Insights"
    ]
)

# =====================================================
# TOP HEADER
# =====================================================

st.markdown("""
<div style='
background:#0D2347;
padding:18px;
border-radius:15px;
border:1px solid rgba(255,255,255,0.08);
margin-bottom:20px;
'>
<h2 style='margin:0;'>🛡️ PhishLog Dashboard</h2>
<p style='color:#B8D8FF;'>Real-time overview of server access logs and security events.</p>
</div>
""", unsafe_allow_html=True)

# =====================================================
# DASHBOARD PAGE
# =====================================================

if menu == "Dashboard":

    st.title("📊 Security Monitoring Dashboard")

    st.markdown(
        "This dashboard provides real-time monitoring and phishing detection analysis using AI and threat intelligence integration."
    )

    st.caption(
        f"Last Updated: {datetime.now().strftime('%d %B %Y, %I:%M %p')}"
    )

    # =================================================
    # FILTER CARD
    # =================================================

    with st.container(border=True):

        st.markdown("## 🎛️ Dashboard Filters")

        f1, f2, f3 = st.columns(3)

        with f1:
            selected_threat = st.multiselect(
                "Threat Severity",
                options=df["threat_label"].unique(),
                default=[]
            )

        with f2:
            selected_protocol = st.multiselect(
                "Network Protocol",
                options=df["protocol"].unique(),
                default=[]
            )

        with f3:
            selected_log = st.multiselect(
                "Log Source",
                options=df["log_type"].unique(),
                default=[]
            )

    filtered_df = df.copy()

    if selected_threat:
        filtered_df = filtered_df[
            filtered_df["threat_label"].isin(selected_threat)
        ]

    if selected_protocol:
        filtered_df = filtered_df[
            filtered_df["protocol"].isin(selected_protocol)
        ]

    if selected_log:
        filtered_df = filtered_df[
            filtered_df["log_type"].isin(selected_log)
        ]

    if len(filtered_df) == 0:
        st.warning("No data available for selected filters.")
        st.stop()

    dashboard_df = filtered_df.sample(
        min(3000, len(filtered_df))
    )

    total_logs = len(dashboard_df)

    suspicious_logs = len(
        dashboard_df[
            dashboard_df["threat_label"] == "suspicious"
        ]
    )

    malicious_logs = len(
        dashboard_df[
            dashboard_df["threat_label"] == "malicious"
        ]
    )

    blocked_requests = len(
        dashboard_df[
            dashboard_df["action"] == "blocked"
        ]
    )

    # =================================================
    # KPI CARDS ROW
    # =================================================

    st.markdown("## 📌 Descriptive Analytics")

    k1, k2, k3, k4 = st.columns(4)

    k1.metric(
        "Total Logs",
        f"{total_logs:,}",
        delta=f"+{total_logs//15}",
        delta_color="normal",
        help="Total number of server access log records currently displayed based on selected filters."
    )

    k2.metric(
        "Suspicious Logs",
        f"{suspicious_logs:,}",
        delta=f"+{suspicious_logs//20}",
        delta_color="inverse",
        help="Suspicious logs indicate activities that may require further investigation."
    )

    k3.metric(
        "Malicious Logs",
        f"{malicious_logs:,}",
        delta=f"+{malicious_logs//25}",
        delta_color="inverse",
        help="Malicious logs represent high-risk activities detected in the monitoring data."
    )

    k4.metric(
        "Blocked Requests",
        f"{blocked_requests:,}",
        delta=f"+{blocked_requests//18}",
        delta_color="normal",
        help="Blocked requests show activities stopped by the security system."
    )

    # =================================================
    # FIRST GRAPH ROW
    # =================================================

    st.markdown("## 🔍 Diagnostic Analytics")

    c1, c2, c3 = st.columns(3)

    with c1:

        with st.container(border=True):

            threat_counts = dashboard_df["threat_label"].value_counts()

            fig1 = px.pie(
                values=threat_counts.values,
                names=threat_counts.index,
                hole=0.6,
                title="Threat Severity Distribution",
                color=threat_counts.index,
                color_discrete_map={
                    "suspicious": "#FFA500",
                    "malicious": "#FF3333",
                    "safe": "#2ECC71"
                }
            )

            fig1.update_layout(
                paper_bgcolor="#0D2347",
                plot_bgcolor="#0D2347",
                font_color="white",
                height=300,
                margin=dict(l=10, r=10, t=50, b=10),
                legend_title="Threat Category"
            )

            fig1.update_traces(
                hovertemplate=
                "<b>Threat Category:</b> %{label}<br>"
                "<b>Total Logs:</b> %{value}<br>"
                "<b>Percentage:</b> %{percent}<br><br>"
                "This shows the proportion of monitored traffic in this threat category."
                "<extra></extra>"
            )

            st.plotly_chart(
                fig1,
                use_container_width=True
            )

    with c2:

        with st.container(border=True):

            protocol_counts = dashboard_df["protocol"].value_counts()

            protocol_df = pd.DataFrame({
                "Protocol": protocol_counts.index,
                "Count": protocol_counts.values
            })

            fig2 = px.bar(
                protocol_df,
                x="Protocol",
                y="Count",
                color="Protocol",
                text="Count",
                title="Protocol Analysis"
            )

            fig2.update_layout(
                paper_bgcolor="#0D2347",
                plot_bgcolor="#0D2347",
                font_color="white",
                height=300,
                margin=dict(l=10, r=10, t=50, b=10),
                legend_title="Protocol Type"
            )

            fig2.update_traces(
                hovertemplate=
                "<b>Protocol:</b> %{x}<br>"
                "<b>Total Logs:</b> %{y}<br><br>"
                "This shows how frequently this protocol appears in the selected logs."
                "<extra></extra>"
            )

            st.plotly_chart(
                fig2,
                use_container_width=True
            )

    with c3:

        with st.container(border=True):

            log_counts = dashboard_df["log_type"].value_counts()

            log_df = pd.DataFrame({
                "Log Source": log_counts.index,
                "Count": log_counts.values
            })

            fig3 = px.bar(
                log_df,
                x="Log Source",
                y="Count",
                color="Log Source",
                text="Count",
                title="Log Source Monitoring"
            )

            fig3.update_layout(
                paper_bgcolor="#0D2347",
                plot_bgcolor="#0D2347",
                font_color="white",
                height=300,
                margin=dict(l=10, r=10, t=50, b=10),
                legend_title="Log Source"
            )

            fig3.update_traces(
                hovertemplate=
                "<b>Log Source:</b> %{x}<br>"
                "<b>Total Records:</b> %{y}<br><br>"
                "This shows which log source contributes the most monitoring activity."
                "<extra></extra>"
            )

            st.plotly_chart(
                fig3,
                use_container_width=True
            )

    # =================================================
    # SECOND GRAPH ROW
    # =================================================

    t1, t2 = st.columns([2, 1])

    with t1:

        with st.container(border=True):

            st.markdown("### 📈 Threat Events Timeline")

            timeline = dashboard_df.groupby(
                dashboard_df["timestamp"].dt.date
            ).size()

            fig4 = px.line(
                x=timeline.index,
                y=timeline.values,
                markers=True,
                title="Threat Activity Trend",
                labels={
                    "x": "Date",
                    "y": "Threat Activity Count"
                }
            )

            fig4.update_layout(
                paper_bgcolor="#0D2347",
                plot_bgcolor="#0D2347",
                font_color="white",
                height=330,
                margin=dict(l=10, r=10, t=50, b=10)
            )

            fig4.update_traces(
                hovertemplate=
                "<b>Date:</b> %{x}<br>"
                "<b>Threat Activity Count:</b> %{y}<br><br>"
                "This point shows the number of threat events detected on this date."
                "<extra></extra>"
            )

            st.plotly_chart(
                fig4,
                use_container_width=True
            )

    with t2:

        with st.container(border=True):

            st.markdown("### 🚦 Threat Action Distribution")

            action_counts = dashboard_df["action"].value_counts()

            blocked_count = action_counts.get("blocked", 0)
            allowed_count = action_counts.get("allowed", 0)

            total_actions = blocked_count + allowed_count

            if total_actions > 0:
                blocked_percent = (blocked_count / total_actions) * 100
                allowed_percent = (allowed_count / total_actions) * 100
            else:
                blocked_percent = 0
                allowed_percent = 0

            threat_action_html = f"""
<div style="background:#0D2347; padding:18px; border-radius:18px; border:1px solid rgba(255,255,255,0.08); font-family:Segoe UI, sans-serif;">

    <p style="color:white; font-weight:600; margin-bottom:10px;">
        ✅ Blocked Requests: {blocked_count:,} ({blocked_percent:.1f}%)
    </p>

    <p style="color:white; font-weight:600; margin-bottom:14px;">
        ⚠️ Allowed Requests: {allowed_count:,} ({allowed_percent:.1f}%)
    </p>

    <div style="width:100%; height:30px; background:#071B34; border-radius:20px; overflow:hidden; display:flex; border:1px solid rgba(255,255,255,0.12);">

        <div style="width:{blocked_percent}%; background:linear-gradient(90deg,#2ECC71,#00C2FF); color:white; text-align:center; line-height:30px; font-weight:bold; font-size:12px;">
            Blocked
        </div>

        <div style="width:{allowed_percent}%; background:linear-gradient(90deg,#FFA500,#FFCC00); color:#071B34; text-align:center; line-height:30px; font-weight:bold; font-size:12px;">
            Allowed
        </div>

    </div>

    <p style="color:#B8D8FF; margin-top:15px; font-size:14px;">
        Compares blocked and allowed requests based on the selected filters.
    </p>

</div>
"""
            st.components.v1.html(
                threat_action_html,
                height=230
            )

    # =================================================
    # PRESCRIPTIVE ANALYTICS ROW
    # =================================================

    st.markdown("## 🛡️ Prescriptive Analytics")

    malicious_percent = (malicious_logs / total_logs) * 100
    suspicious_percent = (suspicious_logs / total_logs) * 100
    blocked_rate = (blocked_requests / total_logs) * 100

    p1, p2, p3 = st.columns(3)

    with p1:

        if malicious_percent >= 40:
            st.error(
                f"🚨 Critical threat level detected. {malicious_percent:.1f}% of monitored logs are malicious."
            )
        elif malicious_percent >= 15:
            st.warning(
                f"⚠️ Elevated malicious activity detected. {malicious_percent:.1f}% of logs contain malicious indicators."
            )
        else:
            st.success(
                f"✅ Malicious activity remains relatively low at {malicious_percent:.1f}%."
            )

    with p2:

        if suspicious_percent >= 50:
            st.warning(
                f"⚠️ High suspicious activity detected. {suspicious_percent:.1f}% of logs contain suspicious behavior."
            )
        elif suspicious_percent >= 20:
            st.info(
                f"🔍 Moderate suspicious activity observed at {suspicious_percent:.1f}%."
            )
        else:
            st.success(
                f"✅ Suspicious activity level is manageable at {suspicious_percent:.1f}%."
            )

    with p3:

        if blocked_rate >= 40:
            st.success(
                f"🛡️ Security protection is actively blocking threats. Blocked rate: {blocked_rate:.1f}%."
            )
        elif blocked_rate >= 10:
            st.info(
                f"🔐 Security systems are filtering suspicious requests. Blocked rate: {blocked_rate:.1f}%."
            )
        else:
            st.warning(
                f"⚠️ Low blocked request activity detected. Blocked rate: {blocked_rate:.1f}%."
            )

    # =================================================
    # TABLE AND EXPORT ROW
    # =================================================

    table_col, export_col = st.columns([2, 1])

    with table_col:

        with st.container(border=True):

            st.markdown("### 🚨 Recent Suspicious Logs")

            suspicious = dashboard_df[
                dashboard_df["threat_label"].isin(
                    [
                        "suspicious",
                        "malicious"
                    ]
                )
            ]

            st.dataframe(
                suspicious[
                    [
                        "timestamp",
                        "log_type",
                        "protocol",
                        "action",
                        "threat_label",
                        "bytes_transferred"
                    ]
                ].tail(10),
                use_container_width=True,
                height=280
            )

    with export_col:

        with st.container(border=True):

            st.markdown("### 📥 Export Reports")

            suspicious_csv = suspicious.to_csv(index=False).encode("utf-8")

            st.download_button(
                label="📥 Download Suspicious Logs CSV",
                data=suspicious_csv,
                file_name="suspicious_logs_report.csv",
                mime="text/csv"
            )

            dashboard_report = (
                f"PhishLog Dashboard Report\n\n"
                f"Last Updated: {datetime.now().strftime('%d %B %Y, %I:%M %p')}\n\n"
                f"Total Logs: {total_logs}\n"
                f"Suspicious Logs: {suspicious_logs}\n"
                f"Malicious Logs: {malicious_logs}\n"
                f"Blocked Requests: {blocked_requests}\n\n"
                f"Summary:\n"
                f"This report summarizes the current cybersecurity monitoring results based on selected dashboard filters."
            )

            st.download_button(
                label="📄 Download Dashboard Summary Report",
                data=dashboard_report,
                file_name="dashboard_summary_report.txt",
                mime="text/plain"
            )

# =====================================================
# SCANNER PAGE
# =====================================================

elif menu == "Scan URL / Text":

    st.title("🔍 AI Threat Scanner")

    st.markdown(
        "Analyze suspicious URLs or phishing-related messages using the trained phishing detection model."
    )

    user_input = st.text_area(
        "Enter suspicious URL or message"
    )

    if st.button("Analyze Threat"):

        if user_input.strip():

            result = classifier(user_input)

            label = result[0]["label"]
            score = result[0]["score"]

            st.markdown("## 🤖 AI Model Prediction")

            if "phishing" in label.lower():

                st.error(
                    f"🚨 Prediction: {label}"
                )

            else:

                st.success(
                    f"✅ Prediction: {label}"
                )

            st.info(
                f"Confidence Score: {score:.2%}"
            )

            vt_input = user_input.strip()
            is_url = is_url_input(vt_input)

            # =================================================
            # VIRUSTOTAL ANALYSIS FOR URL INPUT ONLY
            # =================================================

            if is_url:

                if not vt_input.startswith(("http://", "https://")):

                    vt_input = "https://" + vt_input

                malicious, suspicious = check_url_virustotal(vt_input)

                if malicious is None:

                    malicious = 0

                if suspicious is None:

                    suspicious = 0

                st.markdown("## 🌐 VirusTotal Analysis")

                col1, col2 = st.columns(2)

                col1.metric(
                    "Malicious Detections",
                    malicious
                )

                col2.metric(
                    "Suspicious Detections",
                    suspicious
                )

                if malicious > 0:

                    st.error(
                        "🚨 VirusTotal detected this URL as malicious."
                    )

                else:

                    st.success(
                        "✅ VirusTotal indicates this URL is safe."
                    )

            else:

                malicious = 0
                suspicious = 0

                st.markdown("## 📝 Text-Based Analysis")

                st.info(
                    "VirusTotal analysis was skipped because the input is a text message, not a URL. The result is based on the AI phishing detection model."
                )

            # =================================================
            # FINAL SECURITY VERDICT
            # =================================================

            st.markdown("## 🛡️ Final Security Verdict")

            if is_url and "phishing" in label.lower() and malicious > 0:

                st.error(
                    "🚨 HIGH RISK PHISHING DETECTED"
                )

                st.markdown(
                    "Both the AI model and VirusTotal identified this URL as potentially malicious."
                )

            elif is_url and malicious > 0:

                st.warning(
                    "⚠️ SUSPICIOUS URL DETECTED"
                )

                st.markdown(
                    "VirusTotal identified suspicious activity associated with this URL."
                )

            elif "phishing" in label.lower():

                st.warning(
                    "⚠️ AI MODEL FLAGGED THIS INPUT"
                )

                if is_url:

                    st.markdown(
                        "The AI model detected phishing-related patterns, but VirusTotal did not classify the URL as malicious. This may indicate a false positive."
                    )

                else:

                    st.markdown(
                        "The AI model detected phishing-related patterns in the text message."
                    )

            else:

                st.success(
                    "✅ INPUT APPEARS SAFE"
                )

                st.markdown(
                    "No strong phishing indicators were detected by the AI model."
                )

            # =================================================
            # THREAT ANALYSIS REPORT
            # =================================================

            st.markdown("## 📄 Threat Analysis Report")

            ai_result = label.upper()

            if is_url:

                if malicious > 0:

                    vt_result = "MALICIOUS"

                else:

                    vt_result = "SAFE"

            else:

                vt_result = "NOT APPLICABLE FOR TEXT INPUT"

            if is_url and "phishing" in label.lower() and malicious > 0:

                final_status = "HIGH RISK"

                recommendation = """
                Immediately avoid accessing this URL and block the domain
                from the network firewall or security system.
                """

            elif is_url and malicious > 0:

                final_status = "SUSPICIOUS"

                recommendation = """
                Further investigation is recommended because external
                threat intelligence identified suspicious activity.
                """

            elif "phishing" in label.lower():

                if is_url:

                    final_status = "AI FLAGGED / POSSIBLE FALSE POSITIVE"

                    recommendation = """
                    The AI model flagged this URL as phishing, but VirusTotal
                    did not confirm malicious activity. Review the URL carefully
                    before accessing it.
                    """

                else:

                    final_status = "PHISHING TEXT DETECTED"

                    recommendation = """
                    The message contains phishing-related patterns. Avoid clicking
                    any links, sharing personal information, or responding to the message.
                    """

            else:

                final_status = "SAFE"

                recommendation = """
                No strong phishing indicators were detected from the available analysis.
                """

            report_df = pd.DataFrame({
                "Detection Component": [
                    "AI Model Prediction",
                    "VirusTotal Reputation",
                    "AI Confidence Score",
                    "Final Threat Status"
                ],
                "Result": [
                    ai_result,
                    vt_result,
                    f"{score:.2%}",
                    final_status
                ]
            })

            st.dataframe(
                report_df,
                use_container_width=True,
                hide_index=True
            )

            st.markdown("### 🛡️ Security Recommendation")

            st.info(recommendation)

        else:

            st.warning(
                "Please enter a URL or phishing-related message first."
            )

# =====================================================
# USER MANUAL PAGE
# =====================================================

elif menu == "User Manual":

    st.title("📘 User Manual")

    st.markdown(
        """
        This user manual provides guidance on how to navigate and use the
        Gen-AI Enhanced Server Access Log Monitoring Dashboard for phishing
        detection and cybersecurity monitoring activities.
        """
    )

    st.divider()

    # =================================================
    # DASHBOARD VISUAL GUIDE
    # =================================================

    with st.expander("1️⃣ Dashboard Visual Guide", expanded=True):

        st.components.v1.html(
            textwrap.dedent("""
        <style>

        .guide-wrapper {
            background: linear-gradient(145deg, #071B34, #0D2347);
            border: 1px solid rgba(0,194,255,0.25);
            border-radius: 22px;
            padding: 26px;
            color: white;
            box-shadow: 0px 8px 24px rgba(0,0,0,0.25);
        }

        .guide-intro {
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(0,194,255,0.35);
            border-radius: 16px;
            padding: 18px 22px;
            margin-bottom: 24px;
            color: #D8ECFF;
            font-size: 15px;
            line-height: 1.6;
        }

        .guide-title {
            text-align: center;
            color: #00C2FF;
            font-size: 30px;
            font-weight: 800;
            margin-bottom: 22px;
        }

        .guide-board {
            position: relative;
            background: #0B2447;
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 20px;
            padding: 22px;
            margin-bottom: 22px;
        }

        .guide-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 14px;
            margin-bottom: 16px;
        }

        .guide-chart-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 14px;
            margin-bottom: 16px;
        }

        .guide-bottom-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 14px;
            margin-bottom: 16px;
        }

        .guide-final-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 14px;
        }

        .mock-card {
            background: linear-gradient(145deg, #0D2347, #102B56);
            border: 1px solid rgba(0,194,255,0.22);
            border-radius: 16px;
            padding: 16px;
            min-height: 100px;
            box-shadow: 0px 4px 12px rgba(0,0,0,0.25);
            position: relative;
        }

        .mock-card:hover {
            border: 1px solid #00C2FF;
            box-shadow: 0px 8px 22px rgba(0,194,255,0.25);
            transform: translateY(-4px);
            transition: 0.25s ease-in-out;
        }

        .mock-label {
            color: #7FDBFF;
            font-size: 14px;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .mock-value {
            font-size: 28px;
            font-weight: 800;
            color: white;
        }

        .mock-mini {
            height: 86px;
            border-radius: 12px;
            background:
                linear-gradient(90deg, rgba(0,194,255,0.16), rgba(255,255,255,0.03)),
                repeating-linear-gradient(
                    90deg,
                    rgba(255,255,255,0.08) 0px,
                    rgba(255,255,255,0.08) 1px,
                    transparent 1px,
                    transparent 38px
                );
            border: 1px solid rgba(255,255,255,0.08);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #B8D8FF;
            font-size: 13px;
            font-weight: 600;
            text-align: center;
        }

        .guide-number {
            position: absolute;
            top: -12px;
            left: -10px;
            background: #00C2FF;
            color: #071B34;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
            box-shadow: 0px 4px 12px rgba(0,194,255,0.4);
        }

        .guide-steps-title {
            text-align: center;
            color: #00C2FF;
            font-size: 24px;
            font-weight: 800;
            margin: 20px 0px 16px 0px;
        }

        .guide-steps {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 14px;
        }

        .step-box {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(0,194,255,0.28);
            border-radius: 16px;
            padding: 16px;
            min-height: 150px;
        }

        .step-no {
            background: #00C2FF;
            color: #071B34;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
            margin-bottom: 10px;
        }

        .step-title {
            color: white;
            font-size: 15px;
            font-weight: 800;
            margin-bottom: 8px;
        }

        .step-text {
            color: #B8D8FF;
            font-size: 13px;
            line-height: 1.5;
        }

        @media (max-width: 900px) {
            .guide-grid,
            .guide-chart-grid,
            .guide-bottom-grid,
            .guide-final-grid,
            .guide-steps {
                grid-template-columns: 1fr;
            }
        }

        </style>

        <div class="guide-wrapper">

            <div class="guide-intro">
                <b>ℹ️ Dashboard Overview:</b>
                This visual guide explains the main components of the PhishLog dashboard.
                Users can use this page to understand where to view filters, KPI cards,
                diagnostic graphs, timeline patterns, recommendations, suspicious logs,
                and export features.
            </div>

            <div class="guide-title">
                🛡️ PhishLog Security Monitoring Dashboard Guide
            </div>

            <div class="guide-board">

                <div class="mock-card" style="margin-bottom:16px;">
                    <div class="guide-number">1</div>
                    <div class="mock-label">🎛️ Dashboard Filters</div>
                    <div class="mock-mini">
                        Filter by threat severity, network protocol, and log source
                    </div>
                </div>

                <div class="guide-grid">
                    <div class="mock-card">
                        <div class="guide-number">2</div>
                        <div class="mock-label">Total Logs</div>
                        <div class="mock-value">3,000</div>
                    </div>

                    <div class="mock-card">
                        <div class="mock-label">Suspicious Logs</div>
                        <div class="mock-value">2,251</div>
                    </div>

                    <div class="mock-card">
                        <div class="mock-label">Malicious Logs</div>
                        <div class="mock-value">749</div>
                    </div>

                    <div class="mock-card">
                        <div class="mock-label">Blocked Requests</div>
                        <div class="mock-value">1,503</div>
                    </div>
                </div>

                <div class="guide-chart-grid">
                    <div class="mock-card">
                        <div class="guide-number">3</div>
                        <div class="mock-label">Threat Severity Distribution</div>
                        <div class="mock-mini">Shows suspicious, malicious, and safe traffic proportion</div>
                    </div>

                    <div class="mock-card">
                        <div class="mock-label">Protocol Analysis</div>
                        <div class="mock-mini">Compares protocol usage such as HTTP, HTTPS, SSH, and FTP</div>
                    </div>

                    <div class="mock-card">
                        <div class="mock-label">Log Source Monitoring</div>
                        <div class="mock-mini">Shows which log source contributes the most activity</div>
                    </div>
                </div>

                <div class="guide-bottom-grid">
                    <div class="mock-card">
                        <div class="guide-number">4</div>
                        <div class="mock-label">Threat Events Timeline</div>
                        <div class="mock-mini">Displays threat activity trends over time to detect spikes</div>
                    </div>

                    <div class="mock-card">
                        <div class="guide-number">5</div>
                        <div class="mock-label">Threat Action Distribution</div>
                        <div class="mock-mini">Compares blocked and allowed requests</div>
                    </div>
                </div>

                <div class="guide-final-grid">
                    <div class="mock-card">
                        <div class="guide-number">6</div>
                        <div class="mock-label">Prescriptive Analytics</div>
                        <div class="mock-mini">Provides dynamic security recommendations</div>
                    </div>

                    <div class="mock-card">
                        <div class="guide-number">7</div>
                        <div class="mock-label">Recent Suspicious Logs</div>
                        <div class="mock-mini">Shows the latest suspicious or malicious records</div>
                    </div>

                    <div class="mock-card">
                        <div class="guide-number">8</div>
                        <div class="mock-label">Export Reports</div>
                        <div class="mock-mini">Download suspicious logs CSV or dashboard summary report</div>
                    </div>
                </div>

            </div>

            <div class="guide-steps-title">
                HOW TO USE THIS PAGE
            </div>

            <div class="guide-steps">

                <div class="step-box">
                    <div class="step-no">1</div>
                    <div class="step-title">Apply Filters</div>
                    <div class="step-text">
                        Select threat severity, protocol, or log source to focus on specific cybersecurity activity.
                    </div>
                </div>

                <div class="step-box">
                    <div class="step-no">2</div>
                    <div class="step-title">Review KPI Cards</div>
                    <div class="step-text">
                        Check total logs, suspicious logs, malicious logs, and blocked requests for quick monitoring.
                    </div>
                </div>

                <div class="step-box">
                    <div class="step-no">3</div>
                    <div class="step-title">Analyze Graphs</div>
                    <div class="step-text">
                        Hover over the charts to view values and short explanations about each graph.
                    </div>
                </div>

                <div class="step-box">
                    <div class="step-no">4</div>
                    <div class="step-title">Export Results</div>
                    <div class="step-text">
                        Download suspicious logs or a dashboard summary report for documentation and analysis.
                    </div>
                </div>

            </div>

        </div>
        """),
            height=1300,
            scrolling=True
        )

    # =================================================
    # SIDEBAR NAVIGATION
    # =================================================

    with st.expander("2️⃣ Sidebar Navigation"):

        st.markdown(
            """
            ### 📊 Dashboard
            Displays cybersecurity analytics, threat visualizations,
            suspicious activities, and monitoring information.

            ### 🔍 Scan URL / Text
            Allows users to analyze suspicious URLs or phishing-related
            messages using AI and VirusTotal integration.

            ### 🎣 Phishing Related Insights
            Provides cybersecurity awareness information and phishing
            prevention references.

            ### 📘 User Manual
            Displays guidance and instructions for using the platform.

            ### ℹ️ About
            Provides project background, objectives, technologies used,
            and system features.
            """
        )

    # =================================================
    # FILTER GUIDE
    # =================================================

    with st.expander("3️⃣ How to Use Dashboard Filters"):

        st.markdown(
            """
            The dashboard filters allow users to customize the displayed
            analytics based on selected criteria.

            ### Threat Severity Filter
            Filters logs based on:
            - suspicious
            - malicious
            - safe

            ### Network Protocol Filter
            Filters logs according to protocol types such as:
            - HTTP
            - HTTPS
            - SSH
            - FTP

            ### Log Source Filter
            Filters logs according to security log sources.

            Users may select multiple filter options simultaneously
            to perform deeper cybersecurity analysis.
            """
        )

    # =================================================
    # SCANNER GUIDE
    # =================================================

    with st.expander("4️⃣ How to Use AI Threat Scanner"):

        st.markdown(
            """
            The AI Threat Scanner allows users to analyze suspicious URLs
            or phishing-related messages.

            ### Steps to Use:

            1. Navigate to **Scan URL / Text**
            2. Enter suspicious URL or phishing-related message
            3. Click **Analyze Threat**
            4. Review:
               - AI Model Prediction
               - VirusTotal Analysis
               - Final Security Verdict
               - Threat Analysis Report

            ### Example Inputs:

            - https://example-login-security.com
            - Your account has been suspended. Click here to verify.
            """
        )

    # =================================================
    # UNDERSTANDING RESULTS
    # =================================================

    with st.expander("5️⃣ Understanding Detection Results"):

        st.markdown(
            """
            ### 🤖 AI Model Prediction
            The AI model analyzes phishing-related patterns from
            URLs or text inputs.

            ### 🌐 VirusTotal Analysis
            VirusTotal checks the URL reputation using external
            cybersecurity threat intelligence databases.

            ### 🛡️ Final Security Verdict
            Combines AI prediction and VirusTotal analysis to
            provide the final phishing risk assessment.

            ### 📄 Threat Analysis Report
            Summarizes:
            - AI detection result
            - VirusTotal reputation result
            - Confidence score
            - Final threat status
            """
        )

    # =================================================
    # EXPORT FEATURES
    # =================================================

    with st.expander("6️⃣ Exporting Reports and Logs"):

        st.markdown(
            """
            Users can export cybersecurity monitoring results directly
            from the dashboard.

            ### 📥 Download Suspicious Logs CSV
            Downloads suspicious and malicious log records into CSV format.

            ### 📄 Download Dashboard Summary Report
            Downloads summarized dashboard analytics report including:
            - Total logs
            - Suspicious logs
            - Malicious logs
            - Blocked requests
            """
        )

    # =================================================
    # IMPORTANT NOTES
    # =================================================

    with st.expander("7️⃣ Important Notes"):

        st.warning(
            """
            The AI phishing detection model may occasionally produce
            false positive predictions. Therefore, VirusTotal integration
            is used as additional external threat validation to improve
            phishing analysis reliability.
            """
        )

        st.info(
            """
            This platform is developed for cybersecurity monitoring,
            phishing detection analysis, and educational awareness purposes.
            """
        )

# =====================================================
# ABOUT PAGE
# =====================================================

elif menu == "About":

    st.title("ℹ️ About This Project")

    st.markdown("""
    <style>

    .info-box {
        background: linear-gradient(145deg, #0D2347, #102B56);
        padding: 25px;
        border-radius: 18px;
        border: 1px solid rgba(255,255,255,0.08);
        transition: 0.3s;
        min-height: 230px;
        box-shadow: 0px 4px 12px rgba(0,0,0,0.2);
    }

    .info-box:hover {
        transform: translateY(-8px);
        border: 1px solid #00C2FF;
        box-shadow: 0px 8px 20px rgba(0,194,255,0.25);
    }

    .info-title {
        color: #00C2FF;
        font-size: 24px;
        font-weight: bold;
        margin-bottom: 15px;
    }

    .info-text {
        color: white;
        font-size: 16px;
        line-height: 1.7;
    }

    </style>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:

        st.markdown("""
        <div class="info-box">

        <div class="info-title">
        🎯 Project Objective
        </div>

        <div class="info-text">
        This phishing detection dashboard is developed to help users monitor suspicious server access logs and identify phishing related activities through centralized phishing detection analytics and AI-powered monitoring features.
        </div>

        </div>
        """, unsafe_allow_html=True)

    with col2:

        st.markdown("""
        <div class="info-box">

        <div class="info-title">
        🛡️ System Features
        </div>

        <div class="info-text">
        • Real-time log monitoring<br>
        • Visualization of suspicious log monitoring dashboard<br>
        • URL and phishing message scanning using Hugging Face+VirusTotal API<br>
        • Phishing detection analytics and log monitoring<br>
        • Interactive phishing insights<br>
        </div>

        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col3, col4 = st.columns(2)

    with col3:

        st.markdown("""
        <div class="info-box">

        <div class="info-title">
        ⚙️ Technologies Used
        </div>

        <div class="info-text">
        The dashboard is developed using Streamlit, Python, Pandas, Plotly, fine-tuned BERT model+VirusTotal API to support phishing detection and log monitoring visualization.
        </div>

        </div>
        """, unsafe_allow_html=True)

    with col4:

        st.markdown("""
        <div class="info-box">

        <div class="info-title">
        📊 Dashboard Analytics
        </div>

        <div class="info-text">
        The system provides analytics visualization including protocol distribution, suspicious activity monitoring, log source analysis, threat severity tracking, and timeline-based threat monitoring.
        </div>

        </div>
        """, unsafe_allow_html=True)

    # =====================================================
    # DEVELOPER INFORMATION
    # =====================================================

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown(
        """
<div class="info-box">
    <div class="info-title">👨‍💻 Developer Information</div>
    <div class="info-text">
        <b>Name:</b> Aqmal Hakim Bin Zulkifli<br><br>
        <b>No. Matrix:</b> 2023449352<br><br>
        <b>Email:</b> 2023449352@student.uitm.edu.my
    </div>
</div>
        """,
        unsafe_allow_html=True
    )

# =====================================================
# PHISHING RELATED INSIGHTS
# =====================================================

elif menu == "Phishing Related Insights":

    st.title("🎣 Phishing Related Insights")

    st.markdown("""
    <style>

    .phish-box {
        background: linear-gradient(145deg, #0D2347, #102B56);
        padding: 25px;
        border-radius: 18px;
        border: 1px solid rgba(255,255,255,0.08);
        transition: 0.3s;
        min-height: 270px;
        box-shadow: 0px 4px 12px rgba(0,0,0,0.25);
    }

    .phish-box:hover {
        transform: translateY(-8px);
        border: 1px solid #00C2FF;
        box-shadow: 0px 8px 20px rgba(0,194,255,0.25);
    }

    .phish-title {
        color: #00C2FF;
        font-size: 23px;
        font-weight: bold;
        margin-bottom: 15px;
    }

    .phish-text {
        color: white;
        font-size: 15px;
        line-height: 1.7;
    }

    a {
        color: #4FC3FF !important;
        text-decoration: none;
    }

    a:hover {
        color: #00C2FF !important;
    }

    </style>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:

        st.markdown("""
        <div class="phish-box">

        <div class="phish-title">
        🚨 Suspicious Login Activities
        </div>

        <div class="phish-text">
        Suspicious login attempts in server logs may indicate phishing attacks,
        credential theft, or unauthorized access attempts. Security monitoring
        systems should identify repeated failed logins, unusual access times,
        and abnormal IP activities to reduce cybersecurity risks.
        <br><br>

        🔗 <a href="https://www.cisa.gov/topics/cybersecurity-best-practices" target="_blank">
        Learn More from CISA
        </a>

        </div>

        </div>
        """, unsafe_allow_html=True)

    with col2:

        st.markdown("""
        <div class="phish-box">

        <div class="phish-title">
        🔗 Malicious URL Detection
        </div>

        <div class="phish-text">
        Phishing URLs are commonly used to trick users into revealing sensitive
        information such as passwords and banking credentials. Log monitoring
        systems can identify suspicious domains, shortened URLs, and repeated
        redirection activities associated with phishing campaigns.
        <br><br>

        🔗 <a href="https://www.phishing.org/phishing" target="_blank">
        Learn About Phishing URLs
        </a>

        </div>

        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col3, col4 = st.columns(2)

    with col3:

        st.markdown("""
        <div class="phish-box">

        <div class="phish-title">
        📊 Security Log Monitoring
        </div>

        <div class="phish-text">
        Security logs help cybersecurity analysts identify unusual system
        behaviors, suspicious requests, and abnormal network activities.
        Monitoring protocols such as HTTP, HTTPS, SSH, and FTP can support
        phishing detection and improve incident response strategies.
        <br><br>

        🔗 <a href="https://www.ibm.com/topics/log-management" target="_blank">
        IBM Log Monitoring Guide
        </a>

        </div>

        </div>
        """, unsafe_allow_html=True)

    with col4:

        st.markdown("""
        <div class="phish-box">

        <div class="phish-title">
        🛡️ Phishing Prevention Strategies
        </div>

        <div class="phish-text">
        Organizations should implement multi-factor authentication, firewall
        protection, intrusion detection systems, and cybersecurity awareness
        training to reduce phishing risks. Continuous monitoring and AI-powered
        analytics can further strengthen phishing defense mechanisms.
        <br><br>

        🔗 <a href="https://www.cloudflare.com/learning/access-management/phishing-attack/" target="_blank">
        Cloudflare Phishing Prevention
        </a>

        </div>

        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    st.info(
        "📌 This section provides cybersecurity awareness information and phishing-related and log monitoring insights to improve phishing detection and log monitoring understanding."
    )

# =====================================================
# FIXED FOOTER
# =====================================================

st.markdown(
    """
    <style>

    .fixed-footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background: linear-gradient(90deg, #071B34, #0D2347);
        border-top: 1px solid rgba(0,194,255,0.25);
        color: #7FDBFF;
        text-align: center;
        padding: 10px 0px;
        font-size: 13px;
        z-index: 999;
        box-shadow: 0px -4px 14px rgba(0,0,0,0.35);
    }

    .fixed-footer b {
        color: white;
    }

    </style>

    <div class="fixed-footer">
        © 2026 <b>PhishLog Security Dashboard</b> | Developed by Aqmal Hakim Bin Zulkifli
    </div>
    """,
    unsafe_allow_html=True
)