"""
analyzer.py - URL phishing analysis engine.

Examines a URL against multiple heuristic indicators and produces
a risk score (0–100) and a classification of Safe / Suspicious / Phishing.
"""

import re
import urllib.parse
from typing import Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Keywords commonly associated with phishing pages
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "bank", "secure", "update",
    "password", "signin", "webscr", "ebayisapi", "confirm",
    "billing", "support", "authenticate", "validation", "credential",
    "wallet", "recover", "unlock", "alert", "suspended",
]

# Well-known URL shortening services
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "buff.ly", "adf.ly", "is.gd", "cli.gs", "pic.gd",
    "DwarfURL.com", "snipurl.com", "short.to", "BudURL.com",
    "ping.fm", "post.ly", "Just.as", "bkite.com", "snipr.com",
    "fic.kr", "loopt.us", "doiop.com", "shorty.com", "kl.am",
    "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do",
    "lnkd.in", "db.tt", "qr.ae", "cur.lv", "ity.im",
    "q.gs", "po.st", "bc.vc", "su.pr", "twit.ac",
]

# Suspicious TLDs frequently abused in phishing campaigns
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".pw", ".work", ".date",
    ".racing", ".download", ".win", ".bid", ".party",
]

# Trusted domains that should not trigger IP/keyword checks
TRUSTED_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "twitter.com", "linkedin.com",
    "youtube.com", "wikipedia.org",
]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Return the netloc (host) portion of *url*, lower-cased."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def _is_trusted(domain: str) -> bool:
    """Return True if *domain* belongs to a hard-coded trusted list."""
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


# ---------------------------------------------------------------------------
# Individual indicator checks  (each returns a weight 0–N and a description)
# ---------------------------------------------------------------------------

def check_ip_address(url: str) -> Tuple[int, str | None]:
    """Detect IPv4 addresses used in place of a real domain name. (+30)"""
    ip_pattern = re.compile(
        r"(https?://|@)?"
        r"(\d{1,3}\.){3}\d{1,3}"
    )
    domain = _extract_domain(url)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain):
        return 30, "IP address used instead of a domain name"
    if ip_pattern.search(url):
        return 25, "Numeric IP pattern found in URL"
    return 0, None


def check_url_length(url: str) -> Tuple[int, str | None]:
    """Flag overly long URLs; phishing links often obfuscate behind length. (+15/+10)"""
    length = len(url)
    if length > 100:
        return 15, f"Suspicious URL length ({length} characters — above 100)"
    if length > 75:
        return 10, f"URL length is moderately long ({length} characters)"
    return 0, None


def check_at_symbol(url: str) -> Tuple[int, str | None]:
    """The @ symbol in a URL forces browsers to ignore everything before it. (+25)"""
    # Only flag @ that appear in the URL path/authority (not in query params as %40)
    parsed = urllib.parse.urlparse(url)
    if "@" in (parsed.netloc + parsed.path):
        return 25, "@ symbol detected — browser ignores everything before it"
    return 0, None


def check_subdomain_depth(url: str) -> Tuple[int, str | None]:
    """Excessive sub-domains are a classic phishing obfuscation trick. (+20/+10)"""
    domain = _extract_domain(url)
    # Strip port if present
    domain = domain.split(":")[0]
    parts = domain.split(".")
    # e.g. sub.sub.evil.com → 4 parts → 2 subdomains
    subdomain_count = len(parts) - 2
    if subdomain_count >= 3:
        return 20, f"Excessive subdomains ({subdomain_count}) detected"
    if subdomain_count == 2:
        return 10, f"Multiple subdomains ({subdomain_count}) detected"
    return 0, None


def check_suspicious_keywords(url: str) -> Tuple[int, str | None]:
    """Look for phishing-associated keywords anywhere in the URL. (+5 each, max 20)"""
    url_lower = url.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if not found:
        return 0, None
    score = min(len(found) * 5, 20)
    return score, f"Suspicious keyword(s) found: {', '.join(found[:5])}"


def check_url_shortener(url: str) -> Tuple[int, str | None]:
    """Detect well-known URL shortening services. (+15)"""
    domain = _extract_domain(url).lstrip("www.")
    for shortener in URL_SHORTENERS:
        if domain == shortener.lower() or domain.endswith("." + shortener.lower()):
            return 15, f"URL shortening service detected ({domain})"
    return 0, None


def check_special_characters(url: str) -> Tuple[int, str | None]:
    """Flag excessive hyphens or suspicious character sequences. (+10/+5)"""
    domain = _extract_domain(url)
    hyphen_count = domain.count("-")
    if hyphen_count >= 4:
        return 10, f"Excessive hyphens in domain ({hyphen_count}) — common obfuscation technique"
    if hyphen_count >= 2:
        return 5, f"Multiple hyphens in domain ({hyphen_count})"
    return 0, None


def check_suspicious_tld(url: str) -> Tuple[int, str | None]:
    """Flag free / abused top-level domains commonly used in phishing. (+15)"""
    domain = _extract_domain(url)
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return 15, f"Suspicious TLD detected ({tld})"
    return 0, None


def check_https(url: str) -> Tuple[int, str | None]:
    """Absence of HTTPS is a warning sign (not conclusive on its own). (+10)"""
    if url.lower().startswith("http://"):
        return 10, "URL uses HTTP instead of HTTPS (unencrypted connection)"
    return 0, None


def check_double_slash(url: str) -> Tuple[int, str | None]:
    """Double-slash redirects in the path are a common obfuscation trick. (+5)"""
    path = urllib.parse.urlparse(url).path
    if "//" in path:
        return 5, "Double-slash redirect detected in URL path"
    return 0, None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> dict:
    """
    Run all phishing indicator checks against *url* and return a structured result.

    Returns:
        {
            "url":          str,
            "risk_score":   int (0–100),
            "status":       "Safe" | "Suspicious" | "Phishing",
            "reasons":      list[str],
            "recommendations": list[str],
            "checks":       dict  (raw per-check scores, useful for debugging)
        }
    """
    # Normalise: add scheme if missing
    if not re.match(r"https?://", url, re.IGNORECASE):
        url = "http://" + url

    domain = _extract_domain(url)
    trusted = _is_trusted(domain)

    # Run every indicator
    checks = [
        ("ip_address",          check_ip_address(url)),
        ("url_length",          check_url_length(url)),
        ("at_symbol",           check_at_symbol(url)),
        ("subdomain_depth",     check_subdomain_depth(url)),
        ("suspicious_keywords", check_suspicious_keywords(url)),
        ("url_shortener",       check_url_shortener(url)),
        ("special_characters",  check_special_characters(url)),
        ("suspicious_tld",      check_suspicious_tld(url)),
        ("https_missing",       check_https(url)),
        ("double_slash",        check_double_slash(url)),
    ]

    reasons = []
    raw_scores = {}
    total_weight = 0

    for name, (weight, reason) in checks:
        raw_scores[name] = weight
        if weight > 0 and reason:
            # Trusted domains get a small discount on minor checks
            effective = weight // 2 if (trusted and weight <= 10) else weight
            total_weight += effective
            reasons.append(reason)

    # Clamp score to 0–100
    risk_score = min(total_weight, 100)

    # Classify
    if risk_score >= 60:
        status = "Phishing"
    elif risk_score >= 30:
        status = "Suspicious"
    else:
        status = "Safe"

    # Trusted-domain override: known good domains cannot be Phishing
    if trusted and status == "Phishing":
        status = "Suspicious"
        risk_score = min(risk_score, 59)

    recommendations = _build_recommendations(status, reasons, url)

    return {
        "url": url,
        "risk_score": risk_score,
        "status": status,
        "reasons": reasons if reasons else ["No phishing indicators detected"],
        "recommendations": recommendations,
        "checks": raw_scores,
    }


def _build_recommendations(status: str, reasons: list, url: str) -> list:
    """Generate contextual security recommendations based on the analysis result."""
    recs = []

    if status == "Phishing":
        recs += [
            "Do NOT enter any personal or financial information on this page.",
            "Close this URL immediately and do not share it with others.",
            "Report this URL to your organization's security team.",
            "If you already visited it, change your passwords immediately.",
            "Run a malware scan on your device as a precaution.",
        ]
    elif status == "Suspicious":
        recs += [
            "Proceed with extreme caution — verify the site's legitimacy before interacting.",
            "Do not enter login credentials or payment information.",
            "Check the URL carefully for misspellings of known brands.",
            "Look for a valid HTTPS certificate (padlock icon in your browser).",
            "Contact the organization directly through their official website.",
        ]
    else:
        recs += [
            "The URL appears safe, but always stay vigilant.",
            "Verify the site certificate if prompted for sensitive information.",
            "Keep your browser and security software up to date.",
        ]

    # Add specific tips based on triggered indicators
    if any("IP address" in r for r in reasons):
        recs.append("Legitimate websites use domain names, not raw IP addresses.")
    if any("shortening" in r for r in reasons):
        recs.append("Expand shortened URLs with a service like CheckShortURL before visiting.")
    if any("HTTP" in r for r in reasons):
        recs.append("Never enter sensitive data on non-HTTPS pages.")
    if any("keyword" in r.lower() for r in reasons):
        recs.append("Phishing sites often mimic banking or account-management pages.")

    return recs
