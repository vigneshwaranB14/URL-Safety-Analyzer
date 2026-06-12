import streamlit as st
import re
from urllib.parse import urlparse

# Page Settings
st.set_page_config(
    page_title="URL Safety Checker",
    page_icon="🔍",
    layout="centered"
)

# Sidebar
st.sidebar.title("About")
st.sidebar.info(
    "This tool analyzes URLs and identifies phishing and malicious indicators."
)
st.sidebar.info("Developed by Vigneshwaran B ")

# Main Title
st.title("🔍 URL Safety Checker")
st.write("Check whether a URL is Safe, Suspicious, or Dangerous.")

# Lists
PHISHING_WORDS = [
    "paypal", "login", "verify",
    "account", "secure", "bank",
    "update", "signin"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk",
    ".ml", ".cf", ".gq"
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "cutt.ly"
]

# User Input
url = st.text_input(
    "Enter URL",
    placeholder="https://example.com"
)

# Analyze Button
if st.button("Analyze URL"):

    if not url:
        st.warning("Please enter a URL.")
        st.stop()

    parsed = urlparse(url)

    host = parsed.netloc.lower().replace("www.", "")

    score = 100
    issues = []

    # HTTPS Check
    if parsed.scheme != "https":
        score -= 20
        issues.append("Not using HTTPS")

    # IP Address Check
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
        score -= 30
        issues.append("Using IP address instead of domain")

    # Long URL Check
    if len(url) > 100:
        score -= 10
        issues.append("Very long URL")

    # Suspicious TLD Check
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score -= 20
            issues.append(f"Suspicious domain extension ({tld})")
            break

    # Phishing Keyword Check
    for word in PHISHING_WORDS:
        if word in host:
            score -= 15
            issues.append(f"Phishing keyword detected ({word})")

    # URL Shortener Check
    if host in SHORTENERS:
        score -= 20
        issues.append("URL shortener detected")

    # Too Many Subdomains
    if host.count(".") > 3:
        score -= 15
        issues.append("Too many subdomains")

    # Malware Download Check
    if url.lower().endswith((".exe", ".zip", ".rar")):
        score -= 25
        issues.append("Possible malware download")

    # Special Character Check
    if "%" in url or "@" in url:
        score -= 10
        issues.append("Suspicious special characters")

    # Fake Domain Check
    if re.search(r'c0m|g00gle|faceb00k|amaz0n', host):
        score -= 40
        issues.append("Possible fake domain")

    # Limit score
    score = max(score, 0)

    # Analysis Result
    st.divider()
    st.subheader("Analysis Result")

    st.progress(score / 100)

    st.metric(
        label="Safety Score",
        value=f"{score}/100"
    )

    # Better Classification
    if score >= 90:
        st.success("✅ SAFE URL")

    elif score >= 60:
        st.warning("⚠️ SUSPICIOUS URL")

    else:
        st.error("🚨 DANGEROUS URL")

    # URL Details
    st.subheader("URL Details")

    col1, col2 = st.columns(2)

    with col1:
        st.info(f"🌐 Domain: {host}")

    with col2:
        st.info(f"🔒 Protocol: {parsed.scheme}")

    # Issues
    st.subheader("Issues Found")

    if issues:
        for issue in issues:
            st.write("•", issue)
    else:
        st.success("No issues detected.")

