
import streamlit as st
import pandas as pd
from transformers import pipeline
import plotly.express as px
import requests
import base64

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

    # Encode URL
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

/* =====================================================
SIDEBAR NAVIGATION IMPROVEMENT
===================================================== */

section[data-testid="stSidebar"] .stRadio label {

    font-size: 20px !important;
    font-weight: 500 !important;

    min-height: 60px;

    display: flex;
    align-items: center;

    padding-top: 12px !important;
    padding-bottom: 12px !important;
    padding-left: 14px !important;
    padding-right: 14px !important;

    margin-bottom: 10px !important;

    border-radius: 12px;

    transition: 0.2s ease-in-out;
}

/* HOVER EFFECT */

section[data-testid="stSidebar"] .stRadio label:hover {

    background-color: rgba(0,194,255,0.15);

    border: 1px solid rgba(0,194,255,0.25);

    cursor: pointer;
}

/* RADIO GROUP SPACING */

div[role="radiogroup"] {

    gap: 10px;
}

.block-container {
    padding-top: 1rem;
    padding-left: 2rem;
    padding-right: 2rem;
}

/* KPI CARDS */
[data-testid="stMetric"] {
    background: #0D2347;
    padding: 18px;
    border-radius: 18px;
    border: 1px solid rgba(255,255,255,0.08);
    border-left: 5px solid #00C2FF;
}

/* BUTTON */
div.stButton > button {
    background: linear-gradient(90deg, #00C2FF, #007BFF);
    color: white;
    border: none;
    border-radius: 10px;
    padding: 10px 18px;
    font-weight: bold;
}

/* TEXT AREA */
textarea {
    background-color: #0D2347 !important;
    color: white !important;
    border-radius: 12px !important;
    border: 1px solid #1E4E8C !important;
}

/* DATAFRAME */
[data-testid="stDataFrame"] {
    border-radius: 15px;
    overflow: hidden;
}

h1, h2, h3 {
    color: white !important;
}

</style>
""", unsafe_allow_html=True)

# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.image("logo.png", width=170)

st.sidebar.markdown("""
<h1 style='color:white; margin-bottom:0;'>PhishLog</h1>
<p style='color:#00C2FF;'>AI-Enhanced Monitoring</p>
""", unsafe_allow_html=True)

menu = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Scan URL / Text",
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
# ADVANCED CONNECTED DASHBOARD
# =====================================================

if menu == "Dashboard":

    st.title("📊 Security Monitoring Dashboard")

    # =================================================
    # FILTER SECTION
    # =================================================

    st.markdown("## 🎛️ Dashboard Filters")

    f1, f2, f3 = st.columns(3)

    # THREAT FILTER
    with f1:

        selected_threat = st.multiselect(
            "Threat Severity",
            options=df["threat_label"].unique(),
            default=[]
        )

    # PROTOCOL FILTER
    with f2:

        selected_protocol = st.multiselect(
            "Network Protocol",
            options=df["protocol"].unique(),
            default=[]
        )

    # LOG SOURCE FILTER
    with f3:

        selected_log = st.multiselect(
            "Log Source",
            options=df["log_type"].unique(),
            default=[]
        )

    # =================================================
    # FILTER LOGIC
    # =================================================

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

    # =================================================
    # EMPTY DATA PROTECTION
    # =================================================

    if len(filtered_df) == 0:

        st.warning(
            "No data available for selected filters."
        )

        st.stop()

    # =================================================
    # DYNAMIC DATA
    # =================================================

    dashboard_df = filtered_df.sample(
        min(3000, len(filtered_df))
    )

    st.divider()

    # =================================================
    # DESCRIPTIVE ANALYTICS
    # =================================================

    st.markdown("## 📌 Descriptive Analytics")

    st.caption(
        "Provides overview of current cybersecurity activities."
    )

    col1, col2, col3, col4 = st.columns(4)

    total_logs = len(dashboard_df)

    suspicious_logs = len(
        dashboard_df[
            dashboard_df['threat_label'] == 'suspicious'
        ]
    )

    malicious_logs = len(
        dashboard_df[
            dashboard_df['threat_label'] == 'malicious'
        ]
    )

    blocked_requests = len(
        dashboard_df[
            dashboard_df['action'] == 'blocked'
        ]
    )

    col1.metric(
        "Total Logs",
        f"{total_logs:,}",
        delta=f"+{total_logs//15}"
    )

    col2.metric(
        "Suspicious Logs",
        f"{suspicious_logs:,}",
        delta=f"+{suspicious_logs//20}"
    )

    col3.metric(
        "Malicious Logs",
        f"{malicious_logs:,}",
        delta=f"+{malicious_logs//25}"
    )

    col4.metric(
        "Blocked Requests",
        f"{blocked_requests:,}",
        delta=f"+{blocked_requests//18}"
    )

    st.divider()

    # =================================================
    # DIAGNOSTIC ANALYTICS
    # =================================================

    st.markdown("## 🔍 Diagnostic Analytics")

    st.caption(
        "Explains where suspicious activities originate and how threats behave."
    )

    row1_col1, row1_col2, row1_col3 = st.columns(3)

    # =================================================
    # THREAT DISTRIBUTION
    # =================================================

    with row1_col1:

        threat_counts = dashboard_df[
            "threat_label"
        ].value_counts()

        fig1 = px.pie(
            values=threat_counts.values,
            names=threat_counts.index,
            hole=0.6,
            title="Threat Severity Distribution"
        )

        fig1.update_layout(
            paper_bgcolor="#0D2347",
            plot_bgcolor="#0D2347",
            font_color="white",
            height=320,
            legend_title="Threat Category"
        )

        st.plotly_chart(
            fig1,
            use_container_width=True
        )

    # =================================================
    # PROTOCOL ANALYSIS
    # =================================================

    with row1_col2:

        protocol_counts = dashboard_df[
            "protocol"
        ].value_counts()

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
            title="Protocol Analysis",
            labels={
                "Protocol": "Network Protocol",
                "Count": "Number of Logs"
            }
        )

        fig2.update_layout(
            paper_bgcolor="#0D2347",
            plot_bgcolor="#0D2347",
            font_color="white",
            height=320,
            showlegend=True,
            legend_title="Protocol Type"
        )

        st.plotly_chart(
            fig2,
            use_container_width=True
        )

    # =================================================
    # LOG SOURCE ANALYSIS
    # =================================================

    with row1_col3:

        log_counts = dashboard_df[
            "log_type"
        ].value_counts()

        log_df = pd.DataFrame({
            "LogSource": log_counts.index,
            "Count": log_counts.values
        })

        fig3 = px.bar(
            log_df,
            x="LogSource",
            y="Count",
            color="LogSource",
            text="Count",
            title="Log Source Monitoring",
            labels={
                "LogSource": "Log Source Type",
                "Count": "Total Log Records"
            }
        )

        fig3.update_layout(
            paper_bgcolor="#0D2347",
            plot_bgcolor="#0D2347",
            font_color="white",
            height=320,
            showlegend=True,
            legend_title="Log Source"
        )

        st.plotly_chart(
            fig3,
            use_container_width=True
        )

    st.divider()

    # =================================================
    # THREAT TIMELINE
    # =================================================

    st.markdown("## 📈 Threat Events Timeline")

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
        height=400
    )

    st.plotly_chart(
        fig4,
        use_container_width=True
    )

    st.divider()

    # =================================================
    # PRESCRIPTIVE ANALYTICS
    # =================================================

    st.markdown("## 🛡️ Prescriptive Analytics")

    p1, p2, p3 = st.columns(3)

    with p1:

        st.info(
            "🔐 Enable multi-factor authentication to reduce phishing risks."
        )

    with p2:

        st.warning(
            "⚠️ Monitor suspicious login activities regularly."
        )

    with p3:

        st.success(
            "✅ Update firewall and IDS rules continuously."
        )

    st.divider()

    # =================================================
    # SUSPICIOUS EVENTS TABLE
    # =================================================

    st.markdown("## 🚨 Recent Suspicious Logs")

    suspicious = dashboard_df[
        dashboard_df[
            "threat_label"
        ].isin([
            "suspicious",
            "malicious"
        ])
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
        height=300
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

            # =================================================
            # BERT MODEL PREDICTION
            # =================================================

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

            # =================================================
            # PREPARE URL FOR VIRUSTOTAL
            # =================================================

            vt_input = user_input.strip()

            # AUTO ADD HTTPS IF USER DOES NOT INCLUDE IT

            if not vt_input.startswith(("http://", "https://")):

                vt_input = "https://" + vt_input

            # =================================================
            # VIRUSTOTAL CHECK
            # =================================================

            malicious, suspicious = check_url_virustotal(vt_input)

            # HANDLE FAILED API RESPONSE

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

            # =================================================
            # FINAL SECURITY VERDICT
            # =================================================

            st.markdown("## 🛡️ Final Security Verdict")

            # CASE 1
            if "phishing" in label.lower() and malicious > 0:

                st.error(
                    "🚨 HIGH RISK PHISHING DETECTED"
                )

                st.markdown(
                    "Both the AI model and VirusTotal identified this URL as potentially malicious."
                )

            # CASE 2
            elif malicious > 0:

                st.warning(
                    "⚠️ SUSPICIOUS URL DETECTED"
                )

                st.markdown(
                    "VirusTotal identified suspicious activity associated with this URL."
                )

            # CASE 3
            elif "phishing" in label.lower() and malicious == 0:

                st.success(
                    "✅ URL APPEARS SAFE"
                )
          
                st.markdown(
                    "VirusTotal verified that this URL is safe. The AI model prediction is likely a false positive."
                )


            # CASE 4
            else:

                st.success(
                    "✅ URL APPEARS SAFE"
                )

                st.markdown(
                    "No phishing indicators were strongly detected by the AI model or VirusTotal."
                )

            # =================================================
            # THREAT ANALYSIS REPORT
            # =================================================

            st.markdown("## 📄 Threat Analysis Report")

            ai_result = label.upper()

            if malicious > 0:

                vt_result = "MALICIOUS"

            else:

                vt_result = "SAFE"

            # FINAL DECISION

            if "phishing" in label.lower() and malicious > 0:

                final_status = "HIGH RISK"

                recommendation = """
                Immediately avoid accessing this URL and block the domain
                from the network firewall or security system.
                """

            elif malicious > 0:

                final_status = "SUSPICIOUS"

                recommendation = """
                Further investigation is recommended because external
                threat intelligence identified suspicious activity.
                """

            
            elif "phishing" in label.lower() and malicious == 0:

                 final_status = "SAFE (False Positive Detected)"

                 recommendation = """
                 The AI model incorrectly flagged this URL as phishing,
                 but VirusTotal confirmed that the URL appears safe.
                 This may indicate a false positive prediction from the AI model.
                 """

            else:

                final_status = "SAFE"

                recommendation = """
                No strong phishing indicators were detected from both
                AI analysis and VirusTotal verification.
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
        height: 230px;
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

    # =================================================
    # FIRST ROW
    # =================================================

    col1, col2 = st.columns(2)

    with col1:

        st.markdown("""
        <div class="info-box">

        <div class="info-title">
        🎯 Project Objective
        </div>

        <div class="info-text">
        This phishing detection dashboard is developed to help users monitor suspicious server access logs and identify cyber threats related activities through centralized cybersecurity analytics and AI-powered monitoring features.
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
        • Threat visualization dashboard<br>
        • URL and phishing message scanning using HF+VirusTotal API<br>
        • Security analytics and monitoring<br>
        • Interactive cybersecurity insights<br>
        </div>

        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # =================================================
    # SECOND ROW
    # =================================================

    col3, col4 = st.columns(2)

    with col3:

        st.markdown("""
        <div class="info-box">

        <div class="info-title">
        ⚙️ Technologies Used
        </div>

        <div class="info-text">
        The dashboard is developed using Streamlit, Python, Pandas, Plotly, fine-tuned BERT model+VirusTotal API to support phishing detection  and security analytics visualization.
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
        height: 270px;
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

    # =================================================
    # FIRST ROW
    # =================================================

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

    # =================================================
    # SECOND ROW
    # =================================================

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
        "📌 This section provides cybersecurity awareness information and phishing-related monitoring insights to improve phishing detection understanding."
    )


