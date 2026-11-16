"""
Identity & Identifier Verification Workbench — Enhanced Edition
Install: pip install streamlit requests dnspython phonenumbers
Run:     streamlit run identity_verifier.py

Optional environment variables:
  HIBP_API_KEY
  GOOGLE_SAFE_BROWSING_API_KEY
  OPENCORPORATES_API_KEY

IMPORTANT:
This application checks identifier syntax, technical metadata, and selected public
sources. It does not authenticate a person, establish ownership, or prove that an
identifier belongs to the person presenting it. Use consent, manual review, and
independent evidence for consequential decisions.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import requests
import streamlit as st

APP_TITLE = "Identity Verification Workbench"
APP_VERSION = "2.0"
TIMEOUT = 10
HEADERS = {
    "User-Agent": f"IdentityVerificationWorkbench/{APP_VERSION} (public identifier checks)",
    "Accept": "application/json, text/plain, */*",
}
SESSION = requests.Session()
SESSION.headers.update(HEADERS)

st.set_page_config(
    page_title=APP_TITLE,
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------- Theme / UI ---------------------------

st.markdown("""
<style>
    .block-container {padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1500px;}
    .hero {
        padding: 1.45rem 1.6rem; border-radius: 18px;
        background: linear-gradient(115deg, rgba(49,87,168,.18), rgba(20,160,150,.10));
        border: 1px solid rgba(120,140,180,.25); margin-bottom: 1rem;
    }
    .hero h1 {margin: 0 0 .35rem 0; font-size: 2.1rem;}
    .hero p {margin: 0; opacity: .82;}
    .small-muted {font-size: .86rem; opacity: .72;}
    div[data-testid="stMetric"] {
        border: 1px solid rgba(128,128,128,.22);
        padding: .8rem 1rem; border-radius: 13px;
        background: rgba(128,128,128,.035);
    }
    div.stButton > button[kind="primary"] {border-radius: 10px; min-height: 2.8rem;}
    section[data-testid="stSidebar"] {border-right: 1px solid rgba(128,128,128,.15);}
</style>
""", unsafe_allow_html=True)

# --------------------------- Shared helpers ---------------------------

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def add_result(results, source, status, detail, confidence="Informational", link=""):
    results.append({
        "Source": source,
        "Status": status,
        "Details": str(detail)[:1800],
        "Confidence": confidence,
        "Reference": link or "",
    })


def safe_get(url, *, params=None, headers=None, allow_redirects=True):
    """Bounded HTTP helper. Never logs secrets or request headers."""
    try:
        response = SESSION.get(
            url, params=params, headers=headers, timeout=TIMEOUT,
            allow_redirects=allow_redirects,
        )
        return response, None
    except requests.RequestException as exc:
        return None, f"{type(exc).__name__}: {exc}"


def request_json(url, *, params=None, headers=None):
    response, error = safe_get(url, params=params, headers=headers)
    if error:
        return None, error
    if response.status_code == 404:
        return None, "Not found"
    try:
        response.raise_for_status()
        return response.json(), None
    except requests.HTTPError:
        return None, f"HTTP {response.status_code}"
    except ValueError:
        return None, "The source did not return valid JSON."


def normalize_domain(value: str) -> str:
    raw = value.strip()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    raw = raw.split("/")[0].split("?")[0].split("#")[0].strip(".").lower()
    if raw.startswith("www."):
        raw = raw[4:]
    try:
        return raw.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    labels = domain.rstrip(".").split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    )


def resolve_public_host(host: str):
    """Resolve host and reject local/private/reserved destinations."""
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            addresses = list({ipaddress.ip_address(info[4][0]) for info in infos})
        except (socket.gaierror, ValueError, OSError) as exc:
            return [], f"DNS resolution failed: {exc}"
    if not addresses:
        return [], "No IP addresses returned."
    blocked = [str(ip) for ip in addresses if not ip.is_global]
    if blocked:
        return [], "Host resolves to a non-public address; network request blocked."
    return sorted({str(ip) for ip in addresses}), None


def check_dns(domain: str, results):
    try:
        import dns.resolver
    except ImportError:
        add_result(results, "DNS records", "Not checked",
                   "Install dnspython to enable DNS checks: pip install dnspython")
        return

    for record_type, label in (("A", "DNS IPv4 records"), ("AAAA", "DNS IPv6 records"),
                               ("MX", "Mail exchangers"), ("TXT", "TXT records")):
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=4)
            values = sorted({str(x).rstrip(".") for x in answers})
            if record_type == "TXT":
                values = [v[:180] for v in values[:5]]
            add_result(results, label, "Found", ", ".join(values[:12]), "High")
        except dns.resolver.NoAnswer:
            add_result(results, label, "No records", f"No {record_type} records were returned.", "Medium")
        except dns.resolver.NXDOMAIN:
            add_result(results, label, "Domain not found", "DNS reports that this domain does not exist.", "High")
        except Exception as exc:
            add_result(results, label, "Unavailable", f"{type(exc).__name__}: {exc}", "Low")


def rdap_lookup(identifier: str):
    return request_json(f"https://rdap.org/{quote(identifier, safe=':.')}")


def verify_email(value: str, results):
    email = value.strip()
    if len(email) > 254 or not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", email
    ):
        add_result(results, "Email syntax", "Invalid", "Enter a complete email address. Syntax does not prove mailbox ownership.", "High")
        return

    local, domain = email.rsplit("@", 1)
    add_result(results, "Email syntax", "Valid format",
               f"Local part length: {len(local)}; domain: {domain.lower()}. Mailbox ownership is not verified.", "High")
    check_dns(domain.lower(), results)

    disposable_url = (
        "https://raw.githubusercontent.com/disposable-email-domains/"
        "disposable-email-domains/master/disposable_email_blocklist.conf"
    )
    response, error = safe_get(disposable_url)
    if error:
        add_result(results, "Disposable email list", "Unavailable", error, "Low", disposable_url)
    else:
        listed = {
            line.strip().lower() for line in response.text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        flagged = domain.lower() in listed
        add_result(results, "Disposable email list", "Flagged" if flagged else "Not listed",
                   "Domain appears on the public disposable-domain list." if flagged
                   else "Domain was not found on the downloaded list; this is not proof the mailbox is genuine.",
                   "Medium", disposable_url)

    key = os.getenv("HIBP_API_KEY", "").strip()
    if not key:
        add_result(results, "Have I Been Pwned", "Not configured",
                   "Set HIBP_API_KEY to enable breach lookup. No email was sent to this service.", "Informational",
                   "https://haveibeenpwned.com/")
        return

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}"
    response, error = safe_get(
        url, params={"truncateResponse": "true"},
        headers={"hibp-api-key": key, "user-agent": "IdentityVerificationWorkbench"},
    )
    if error:
        add_result(results, "Have I Been Pwned", "Unavailable", error, "Low")
    elif response.status_code == 404:
        add_result(results, "Have I Been Pwned", "No breach returned",
                   "No matching breach was returned by this service; this does not mean the account is secure.",
                   "Medium", "https://haveibeenpwned.com/")
    elif response.status_code == 200:
        try:
            breaches = response.json()
            names = [b.get("Name", "Unknown") for b in breaches]
            add_result(results, "Have I Been Pwned", "Breach exposure found",
                       f"{len(names)} breach record(s): {', '.join(names[:10])}", "High",
                       "https://haveibeenpwned.com/")
        except ValueError:
            add_result(results, "Have I Been Pwned", "Invalid response", "Could not parse provider response.", "Low")
    else:
        add_result(results, "Have I Been Pwned", f"HTTP {response.status_code}",
                   response.text[:250], "Low")


def verify_phone(value: str, results, default_region="US"):
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone as phone_timezone
    except ImportError:
        add_result(results, "Phone metadata", "Not checked",
                   "Install phonenumbers: pip install phonenumbers")
        return
    try:
        number = phonenumbers.parse(value.strip(), default_region)
        possible = phonenumbers.is_possible_number(number)
        valid = phonenumbers.is_valid_number(number)
        e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
        region = geocoder.description_for_number(number, "en") or "Not supplied"
        carrier_name = carrier.name_for_number(number, "en") or "Not supplied"
        zones = ", ".join(phone_timezone.time_zones_for_number(number)) or "Not supplied"
        add_result(results, "Phone numbering plan", "Valid number" if valid else "Not valid",
                   f"E.164: {e164}; possible: {possible}; region metadata: {region}; "
                   f"carrier metadata: {carrier_name}; time zones: {zones}", "Medium")
        add_result(results, "Phone ownership", "Not verified",
                   "Numbering-plan data cannot establish who owns, controls, or currently uses this number.", "Informational")
    except Exception as exc:
        add_result(results, "Phone metadata", "Could not parse",
                   f"{type(exc).__name__}: {exc}", "Medium")


def verify_domain(value: str, results):
    domain = normalize_domain(value)
    if not is_valid_domain(domain):
        add_result(results, "Domain syntax", "Invalid", "Enter a domain such as example.com.", "High")
        return
    add_result(results, "Domain syntax", "Valid", domain, "High")
    check_dns(domain, results)

    data, error = rdap_lookup(domain)
    if data:
        events = data.get("events", [])
        registration = next((e.get("eventDate") for e in events
                             if e.get("eventAction") in ("registration", "registered")), None)
        registrar_found = any("registrar" in e.get("roles", []) for e in data.get("entities", []))
        add_result(results, "Domain RDAP registration", "Record found",
                   f"Registered name: {data.get('ldhName', domain)}; registration date: "
                   f"{registration or 'not supplied'}; registrar entity: "
                   f"{'identified' if registrar_found else 'not identified'}",
                   "High", "https://rdap.org/")
    else:
        add_result(results, "Domain RDAP registration", "Unavailable",
                   error or "No RDAP record returned.", "Low", "https://rdap.org/")

    # Prevent requests to localhost, private networks, and other non-public targets.
    addresses, resolve_error = resolve_public_host(domain)
    if resolve_error:
        add_result(results, "Website reachability", "Blocked / unavailable", resolve_error, "High")
        return
    add_result(results, "Resolved public addresses", "Found", ", ".join(addresses), "High")
    try:
        response = SESSION.get(
            f"https://{domain}", timeout=TIMEOUT, allow_redirects=False,
            headers={"Range": "bytes=0-0"},
        )
        add_result(results, "HTTPS response", f"HTTP {response.status_code}",
                   f"Initial response only; redirects are not followed. Server: "
                   f"{response.headers.get('Server', 'not disclosed')}",
                   "Medium", f"https://{domain}")
    except requests.RequestException as exc:
        add_result(results, "HTTPS response", "No response",
                   f"{type(exc).__name__}: {exc}", "Low")


def verify_ip(value: str, results):
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        add_result(results, "IP syntax", "Invalid", "Enter a valid IPv4 or IPv6 address.", "High")
        return
    add_result(results, "IP address classification", "Valid",
               f"{ip} ({'IPv4' if ip.version == 4 else 'IPv6'}); globally routable: "
               f"{ip.is_global}; private: {ip.is_private}; reserved: {ip.is_reserved}", "High")
    if ip.is_global:
        try:
            hostname, aliases, _ = socket.gethostbyaddr(str(ip))
            add_result(results, "Reverse DNS", "PTR record found",
                       f"{hostname}; aliases: {', '.join(aliases[:5]) or 'none'}", "Medium")
        except (socket.herror, socket.gaierror, OSError) as exc:
            add_result(results, "Reverse DNS", "No PTR record", str(exc), "Low")
    else:
        add_result(results, "Reverse DNS", "Not checked",
                   "Reverse lookup skipped for non-public IP addresses.", "Informational")
    data, error = rdap_lookup(str(ip))
    if data:
        add_result(results, "IP RDAP registration", "Record found",
                   f"Network: {data.get('name', 'Unknown')}; handle: "
                   f"{data.get('handle', 'Unknown')}; country: {data.get('country', 'Not supplied')}",
                   "High", "https://rdap.org/")
    else:
        add_result(results, "IP RDAP registration", "Unavailable",
                   error or "No registration data returned.", "Low")


def verify_url(value: str, results):
    raw = value.strip()
    candidate = raw if re.match(r"^https?://", raw, re.I) else "https://" + raw
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname
        if parsed.scheme not in ("http", "https") or not host or parsed.username or parsed.password:
            raise ValueError("Use a valid http(s) URL without embedded username/password credentials.")
        # Accessing .port also validates malformed port syntax.
        _ = parsed.port
    except ValueError as exc:
        add_result(results, "URL syntax", "Invalid", str(exc), "High")
        return

    add_result(results, "URL syntax", "Valid",
               f"Host: {host}; scheme: {parsed.scheme}; path is not submitted to domain-only checks.",
               "High")
    # Check the hostname only. Do not fetch arbitrary user-supplied paths.
    verify_domain(host, results)

    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not key:
        add_result(results, "Google Safe Browsing", "Not configured",
                   "Set GOOGLE_SAFE_BROWSING_API_KEY to enable URL reputation checks.", "Informational",
                   "https://safebrowsing.google.com/")
        return
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={quote(key, safe='')}"
    payload = {
        "client": {"clientId": "identity-verification-workbench", "clientVersion": APP_VERSION},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": candidate}],
        },
    }
    try:
        response = SESSION.post(endpoint, json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        matches = response.json().get("matches", [])
        add_result(results, "Google Safe Browsing",
                   "Threat match found" if matches else "No threat match returned",
                   json.dumps(matches[:3]) if matches else
                   "No match is not a guarantee that this URL is safe.",
                   "High", "https://safebrowsing.google.com/")
    except (requests.RequestException, ValueError) as exc:
        add_result(results, "Google Safe Browsing", "Unavailable",
                   f"{type(exc).__name__}: {exc}", "Low")


def verify_username(value: str, results):
    username = value.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,39}", username):
        add_result(results, "Username syntax", "Review",
                   "Username does not fit the common GitHub username format.", "Medium")
        return
    add_result(results, "Username syntax", "Valid format", username, "High")
    data, error = request_json(f"https://api.github.com/users/{quote(username, safe='')}")
    if data:
        add_result(results, "GitHub public profile", "Profile found",
                   f"Login: {data.get('login')}; public repositories: {data.get('public_repos')}; "
                   f"created: {data.get('created_at')}. This confirms only a public profile exists.",
                   "High", data.get("html_url", ""))
    elif error == "Not found":
        add_result(results, "GitHub public profile", "No matching profile",
                   "No public GitHub account was returned for this exact username.", "Medium",
                   "https://github.com/")
    else:
        add_result(results, "GitHub public profile", "Unavailable", error or "No data returned.", "Low")
    add_result(results, "Other platforms", "Not checked",
               "No cross-platform identity matching is performed. Similar usernames can belong to different people.")


def verify_company(value: str, results):
    name = value.strip()
    if len(name) < 2:
        add_result(results, "Company name", "Invalid", "Enter at least two characters.", "High")
        return
    params = {"q": name}
    key = os.getenv("OPENCORPORATES_API_KEY", "").strip()
    if key:
        params["api_token"] = key
    data, error = request_json("https://api.opencorporates.com/v0.4/companies/search", params=params)
    if data:
        companies = data.get("results", {}).get("companies", [])
        if companies:
            for item in companies[:8]:
                company = item.get("company", {})
                add_result(results, "OpenCorporates registry", "Possible match",
                           f"{company.get('name')} | jurisdiction: {company.get('jurisdiction_code')} | "
                           f"status: {company.get('current_status') or 'not supplied'} | "
                           f"company number: {company.get('company_number')}",
                           "Medium", company.get("opencorporates_url", ""))
        else:
            add_result(results, "OpenCorporates registry", "No match returned",
                       "No matching company was returned; registry coverage varies.", "Medium",
                       "https://opencorporates.com/")
    else:
        add_result(results, "OpenCorporates registry", "Unavailable",
                   error or "No data returned. An API key may be required.", "Low")
    add_result(results, "Company verification", "Manual corroboration required",
               "Confirm the legal name, registration number, jurisdiction, status, and address with the relevant official registry.")


CHECKS = {
    "Email address": verify_email,
    "Phone number": verify_phone,
    "Website URL": verify_url,
    "Domain name": verify_domain,
    "IP address": verify_ip,
    "Username": verify_username,
    "Company / business": verify_company,
}

PLACEHOLDERS = {
    "Email address": "person@example.com",
    "Phone number": "+1 617 555 0123",
    "Website URL": "https://example.com/login",
    "Domain name": "example.com",
    "IP address": "8.8.8.8",
    "Username": "github_username",
    "Company / business": "Example Corporation",
}


def assess(results):
    statuses = [r["Status"].lower() for r in results]
    flags = sum(any(term in s for term in ("invalid", "flagged", "threat match", "not valid", "blocked"))
                for s in statuses)
    positives = sum(any(term in s for term in ("valid", "found", "record found", "profile found", "not listed"))
                    for s in statuses)
    unavailable = sum(any(term in s for term in ("unavailable", "not configured", "not checked"))
                      for s in statuses)
    if flags:
        verdict = "Review required"
    elif positives >= 2:
        verdict = "Technical evidence found"
    else:
        verdict = "Insufficient evidence"
    return verdict, positives, flags, unavailable


def run_check(kind, value, region="US"):
    results = []
    if kind == "Phone number":
        verify_phone(value, results, region)
    else:
        CHECKS[kind](value, results)
    return results


def render_results(kind, value, results):
    verdict, positives, flags, unavailable = assess(results)
    st.subheader("Assessment")
    a, b, c, d = st.columns(4)
    a.metric("Overall assessment", verdict)
    b.metric("Evidence items", positives)
    c.metric("Items to review", flags)
    d.metric("Unavailable checks", unavailable)
    st.caption(
        f"Identifier type: {kind} · Checked: {now_utc()} · "
        "Assessment is a triage aid, not an identity score."
    )

    st.dataframe(results, use_container_width=True, hide_index=True,
                 column_config={
                     "Reference": st.column_config.LinkColumn("Reference", display_text="Open source"),
                     "Confidence": st.column_config.TextColumn("Evidence level"),
                 })
    report = {
        "application": APP_TITLE,
        "version": APP_VERSION,
        "identifier_type": kind,
        "identifier": value,
        "checked_at_utc": now_utc(),
        "assessment": verdict,
        "counts": {"evidence": positives, "review": flags, "unavailable": unavailable},
        "results": results,
        "disclaimer": "Technical/public-source checks do not prove identity, ownership, or authorization.",
    }
    left, right = st.columns(2)
    left.download_button("⬇ Download JSON report", json.dumps(report, indent=2),
                         file_name="identity_check_report.json", mime="application/json",
                         use_container_width=True)
    csv_buffer = io.StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=["Source", "Status", "Details", "Confidence", "Reference"])
    writer.writeheader()
    writer.writerows(results)
    right.download_button("⬇ Download CSV evidence", csv_buffer.getvalue(),
                          file_name="identity_check_evidence.csv", mime="text/csv",
                          use_container_width=True)
    return report


# --------------------------- Application ---------------------------

st.markdown(f"""
<div class="hero">
  <h1>🔎 {APP_TITLE}</h1>
  <p>Multi-source identifier research · Evidence-first reporting · Privacy-conscious checks</p>
</div>
""", unsafe_allow_html=True)

st.warning(
    "**Important limitation:** This tool checks identifiers and selected public/technical sources. "
    "It cannot prove a person's identity, ownership, consent, or authorization. "
    "Do not use it as the sole basis for decisions about employment, housing, credit, insurance, "
    "healthcare, access, or service eligibility."
)

with st.sidebar:
    st.header("Workbench")
    st.caption(f"Version {APP_VERSION}")
    st.markdown("### Optional integrations")
    integrations = [
        ("HIBP_API_KEY", "Email breach exposure"),
        ("GOOGLE_SAFE_BROWSING_API_KEY", "URL threat reputation"),
        ("OPENCORPORATES_API_KEY", "Company registry lookup"),
    ]
    for env_name, purpose in integrations:
        configured = bool(os.getenv(env_name, "").strip())
        st.write(("🟢" if configured else "⚪") + f" **{purpose}**")
        st.caption(f"`{env_name}` · {'Configured' if configured else 'Not configured'}")
    st.divider()
    st.markdown("### Install")
    st.code("pip install streamlit requests dnspython phonenumbers", language="bash")
    st.markdown("### Launch")
    st.code("streamlit run identity_verifier.py", language="bash")
    st.caption("API keys belong in environment variables or Streamlit secrets, never in source code.")

single_tab, batch_tab, guide_tab = st.tabs(["🔍 Single check", "📚 Batch checks", "ℹ️ Guide"])

with single_tab:
    left, right = st.columns([1.05, 1.5], gap="large")
    with left:
        kind = st.selectbox("Identifier type", list(CHECKS.keys()), key="single_kind")
        region = "US"
        if kind == "Phone number":
            region = st.selectbox("Default phone region (for numbers without +country code)",
                                  ["US", "CA", "GB", "AU", "IN", "IE", "NZ"], index=0)
        value = st.text_area("Identifier to check", placeholder=PLACEHOLDERS[kind],
                             height=90, key="single_value")
        st.caption("Only submit information you are authorized to check. Avoid pasting passwords, SSNs, payment data, or government ID numbers.")
        run_single = st.button("Run verification", type="primary",
                               disabled=not value.strip(), use_container_width=True)
    with right:
        st.markdown("#### What this check can tell you")
        descriptions = {
            "Email address": "Syntax, domain DNS/mail configuration, disposable-domain list, and optional breach exposure.",
            "Phone number": "Numbering-plan validity and public numbering metadata. No call, SMS, or ownership test is performed.",
            "Website URL": "URL parsing, hostname/domain evidence, and optional Safe Browsing reputation.",
            "Domain name": "DNS records, RDAP registration metadata, and a restricted HTTPS reachability check.",
            "IP address": "IP classification, reverse DNS, and RDAP network registration metadata.",
            "Username": "Basic syntax and a public GitHub profile lookup only.",
            "Company / business": "Possible public registry matches. A name match is not proof of a real or authorized business.",
        }
        st.info(descriptions[kind])
        st.markdown("#### Evidence standards")
        st.markdown(
            "- **High:** A specific technical response or syntax result.\n"
            "- **Medium:** A source match or metadata that needs corroboration.\n"
            "- **Low / unavailable:** Weak, incomplete, or failed source response.\n"
            "- **Not checked:** The integration or dependency is not enabled."
        )

    if run_single:
        with st.spinner("Querying available sources…"):
            single_results = run_check(kind, value, region)
        st.session_state["last_report"] = {
            "kind": kind, "value": value, "results": single_results,
        }
        st.divider()
        render_results(kind, value, single_results)

    elif st.session_state.get("last_report"):
        previous = st.session_state["last_report"]
        with st.expander("Show most recent check from this session", expanded=False):
            st.caption(f"{previous['kind']}: {previous['value']}")
            st.dataframe(previous["results"], use_container_width=True, hide_index=True)

with batch_tab:
    st.markdown("#### Check a list of identifiers")
    batch_kind = st.selectbox("Identifier type for this batch", list(CHECKS.keys()), key="batch_kind")
    batch_text = st.text_area(
        "Paste one identifier per line",
        placeholder="person1@example.com\nperson2@example.com",
        height=160,
        key="batch_text",
    )
    max_items = st.slider("Maximum items in this run", min_value=1, max_value=25, value=10)
    st.caption("Batch mode runs the same public/technical checks for each line. It does not match people across identifiers.")
    run_batch = st.button("Run batch checks", type="primary",
                          disabled=not batch_text.strip(), use_container_width=True)
    if run_batch:
        values = list(dict.fromkeys(line.strip() for line in batch_text.splitlines() if line.strip()))
        if len(values) > max_items:
            st.warning(f"{len(values)} lines supplied. Only the first {max_items} unique entries will be checked.")
            values = values[:max_items]
        batch_rows = []
        all_results = []
        progress = st.progress(0, text="Starting checks…")
        for index, item in enumerate(values):
            item_results = run_check(batch_kind, item)
            verdict, positives, flags, unavailable = assess(item_results)
            batch_rows.append({
                "Identifier": item,
                "Assessment": verdict,
                "Evidence": positives,
                "Review": flags,
                "Unavailable": unavailable,
                "Sources checked": len(item_results),
            })
            for result in item_results:
                all_results.append({"Identifier": item, **result})
            progress.progress((index + 1) / len(values), text=f"Checked {index + 1} of {len(values)}")
            time.sleep(0.05)
        st.session_state["last_batch"] = {
            "kind": batch_kind, "rows": batch_rows, "results": all_results,
        }
        st.success(f"Completed {len(values)} item(s).")
        st.dataframe(batch_rows, use_container_width=True, hide_index=True)
        batch_csv = io.StringIO()
        writer = csv.DictWriter(batch_csv, fieldnames=list(batch_rows[0].keys()))
        writer.writeheader()
        writer.writerows(batch_rows)
        st.download_button("⬇ Download batch summary (CSV)", batch_csv.getvalue(),
                           file_name="identity_batch_summary.csv", mime="text/csv")
        detail_json = json.dumps({
            "identifier_type": batch_kind, "checked_at_utc": now_utc(),
            "summary": batch_rows, "evidence": all_results,
            "disclaimer": "These checks do not prove real-world identity or ownership.",
        }, indent=2)
        st.download_button("⬇ Download full batch evidence (JSON)", detail_json,
                           file_name="identity_batch_evidence.json", mime="application/json")

with guide_tab:
    st.markdown("### How to interpret the workbench")
    st.markdown("""
| Result | Meaning |
|---|---|
| Valid / Found | A format or technical/public-source response was returned. |
| Flagged / Threat match | Investigate the finding and verify it with the source. |
| No match | That source returned no match; coverage may be incomplete. |
| Unavailable | A provider, network, or API request failed. |
| Not configured / Not checked | An optional key or dependency is missing. |

### Recommended verification workflow
1. Confirm that you have a lawful purpose and authorization to check the identifier.
2. Start with syntax and technical checks.
3. Corroborate material findings with an authoritative source.
4. Ask the individual or organization to complete an appropriate verification step when ownership matters.
5. Record the source, timestamp, and limitations of each finding.

### What this application intentionally does not do
- It does not search for, infer, or identify a private individual.
- It does not test passwords, bypass authentication, or access private accounts.
- It does not send verification texts, calls, or emails.
- It does not infer that two identifiers belong to the same person.
- It does not make automated eligibility, fraud, or trust decisions.
""")
    st.info("For actual identity proofing, use a consent-based identity verification provider with documented legal, security, and privacy controls.")

st.divider()
st.caption(
    f"{APP_TITLE} v{APP_VERSION} · Results are time-sensitive and provider-dependent. "
    "Review provider terms, rate limits, privacy requirements, and local law before use."
)
