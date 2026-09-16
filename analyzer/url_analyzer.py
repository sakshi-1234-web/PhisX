import ipaddress
import re
from urllib.parse import urlparse


# =========================================================
# CONFIGURATION
# =========================================================

# Common URL-shortening services.
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
}

# Suspicious TLDs used as warning signals.
SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
}

# Common paths associated with credential/account activity.
SUSPICIOUS_LOGIN_PATHS = {
    "/login",
    "/signin",
    "/verify",
    "/account",
    "/password",
}


# =========================================================
# URL EXTRACTION
# =========================================================

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)


def extract_urls(text):
    """
    Extract HTTP and HTTPS URLs from text.

    This function only extracts URLs.
    It does NOT visit or request them.
    """

    if not isinstance(text, str):
        return []

    urls = URL_PATTERN.findall(text)

    cleaned_urls = []

    for url in urls:

        # Remove punctuation commonly placed after URLs
        # in normal email sentences.
        url = url.rstrip(".,!?;:)]}")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


# =========================================================
# DOMAIN HELPERS
# =========================================================

def get_domain(url):
    """
    Extract the hostname/domain from a URL.
    """

    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def get_tld(domain):
    """
    Return the apparent top-level domain.
    """

    if not domain or "." not in domain:
        return ""

    return "." + domain.rsplit(".", 1)[1].lower()


def is_ip_address(domain):
    """
    Check whether a URL hostname is an IPv4 or IPv6 address.
    """

    if not domain:
        return False

    cleaned_domain = domain.strip("[]")

    try:
        ipaddress.ip_address(cleaned_domain)
        return True
    except ValueError:
        return False


# =========================================================
# URL FEATURE DETECTION
# =========================================================

def is_shortened_url(domain):
    """
    Check whether the domain belongs to a known
    URL-shortening service.
    """

    return domain in URL_SHORTENERS


def has_suspicious_tld(domain):
    """
    Check for suspicious TLDs configured for this MVP.
    """

    return get_tld(domain) in SUSPICIOUS_TLDS


def has_login_path(url):
    """
    Check whether the URL contains a path commonly
    associated with account or credential activity.
    """

    try:
        parsed = urlparse(url)

        path = parsed.path.lower().rstrip("/")

        if path in SUSPICIOUS_LOGIN_PATHS:
            return True

        # Also detect nested login-like paths such as:
        # /secure/login
        # /account/verify
        # /user/password/reset
        path_parts = {
            part
            for part in path.split("/")
            if part
        }

        suspicious_parts = {
            "login",
            "signin",
            "verify",
            "account",
            "password",
        }

        return bool(path_parts.intersection(suspicious_parts))

    except ValueError:
        return False


def is_unusually_long(url):
    """
    Detect unusually long URLs or large query strings.

    This is only a warning signal and is not proof
    that a URL is malicious.
    """

    if len(url) > 2000:
        return True

    try:
        parsed = urlparse(url)

        if len(parsed.query) > 500:
            return True

    except ValueError:
        return False

    return False


def has_excessive_encoding(url):
    """
    Detect excessive percent-encoding in a URL.
    """

    encoded_parts = re.findall(
        r"%[0-9a-fA-F]{2}",
        url,
    )

    return len(encoded_parts) >= 8


# =========================================================
# INDIVIDUAL URL ANALYSIS
# =========================================================

def analyze_single_url(url):
    """
    Analyze one URL using static characteristics.

    No network request is made.
    """

    domain = get_domain(url)

    findings = []
    score = 0

    # -----------------------------------------------------
    # Invalid / missing domain
    # -----------------------------------------------------

    if not domain:

        findings.append({
            "indicator": "Malformed URL",
            "severity": "MEDIUM",
            "description": (
                "The URL could not be parsed as a normal web address."
            ),
            "score_contribution": 8,
        })

        return {
            "url": url,
            "domain": "",
            "score": 8,
            "findings": findings,
        }

    # -----------------------------------------------------
    # IP-based URL
    # -----------------------------------------------------

    if is_ip_address(domain):

        findings.append({
            "indicator": "IP-based URL",
            "severity": "HIGH",
            "description": (
                "The URL points directly to an IP address instead "
                "of using a conventional domain name."
            ),
            "score_contribution": 15,
        })

        score += 15

    # -----------------------------------------------------
    # Suspicious TLD
    # -----------------------------------------------------

    if has_suspicious_tld(domain):

        findings.append({
            "indicator": "Suspicious URL domain",
            "severity": "MEDIUM",
            "description": (
                f"The URL uses the {get_tld(domain)} top-level domain, "
                "which is treated as a warning signal by this MVP."
            ),
            "score_contribution": 8,
        })

        score += 8

    # -----------------------------------------------------
    # URL shortener
    # -----------------------------------------------------

    if is_shortened_url(domain):

        findings.append({
            "indicator": "URL shortener detected",
            "severity": "MEDIUM",
            "description": (
                "The URL uses a shortening service that hides "
                "the final destination."
            ),
            "score_contribution": 6,
        })

        score += 6

    # -----------------------------------------------------
    # Suspicious login/account path
    # -----------------------------------------------------

    if has_login_path(url):

        findings.append({
            "indicator": "Credential-related URL path",
            "severity": "MEDIUM",
            "description": (
                "The URL contains a login, account, verification, "
                "or password-related path."
            ),
            "score_contribution": 5,
        })

        score += 5

    # -----------------------------------------------------
    # Unusually long URL
    # -----------------------------------------------------

    if is_unusually_long(url):

        findings.append({
            "indicator": "Unusually long URL",
            "severity": "LOW",
            "description": (
                "The URL is unusually long or contains a large "
                "query string."
            ),
            "score_contribution": 4,
        })

        score += 4

    # -----------------------------------------------------
    # Excessive URL encoding
    # -----------------------------------------------------

    if has_excessive_encoding(url):

        findings.append({
            "indicator": "Excessive URL encoding",
            "severity": "MEDIUM",
            "description": (
                "The URL contains an unusually high amount of "
                "percent-encoded data."
            ),
            "score_contribution": 5,
        })

        score += 5

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "findings": findings,
    }


# =========================================================
# URL ANALYZER
# =========================================================

def analyze_urls(text):
    """
    Extract and analyze every URL found in the email.

    The overall URL contribution is capped at 35 points.
    """

    urls = extract_urls(text)

    analyzed_urls = []
    total_score = 0

    for url in urls:

        result = analyze_single_url(url)

        analyzed_urls.append(result)

        total_score += result["score"]

    # -----------------------------------------------------
    # Cap total URL contribution at 35 points
    # -----------------------------------------------------

    total_score = min(total_score, 35)

    # -----------------------------------------------------
    # Flatten findings for convenient use by threat engine
    # -----------------------------------------------------

    findings = []

    for result in analyzed_urls:
        findings.extend(result["findings"])

    return {
        "score": total_score,
        "urls": analyzed_urls,
        "findings": findings,
    }