import ipaddress
import re
from urllib.parse import urlparse


# =========================================================
# CONFIGURATION
# =========================================================

# Suspicious TLDs requested for the MVP.
SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
}

# Common free email providers.
FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "aol.com",
}

# Organizations commonly targeted by impersonation.
# This is deliberately a small MVP list.
KNOWN_ORGANIZATIONS = {
    "paypal",
    "microsoft",
    "apple",
    "google",
    "amazon",
    "netflix",
    "instagram",
    "facebook",
    "linkedin",
    "github",
    "docusign",
    "dropbox",
}


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_PATTERN = re.compile(
    r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$",
    re.IGNORECASE,
)


def is_valid_email(email):
    """
    Perform basic sender email validation.

    This is intentionally not a full RFC email validator.
    It is sufficient for the MVP.
    """

    if not isinstance(email, str):
        return False

    return bool(EMAIL_PATTERN.fullmatch(email.strip()))


# =========================================================
# DOMAIN EXTRACTION
# =========================================================

def extract_domain(email):
    """
    Extract the domain portion from an email address.
    """

    if not isinstance(email, str) or "@" not in email:
        return ""

    return email.rsplit("@", 1)[1].strip().lower()


# =========================================================
# IP DOMAIN DETECTION
# =========================================================

def is_ip_address(domain):
    """
    Determine whether the sender domain is an IPv4 or IPv6 address.
    """

    if not domain:
        return False

    # Remove brackets sometimes used around IPv6 addresses.
    cleaned_domain = domain.strip("[]")

    try:
        ipaddress.ip_address(cleaned_domain)
        return True
    except ValueError:
        return False


# =========================================================
# TLD DETECTION
# =========================================================

def get_tld(domain):
    """
    Return the apparent top-level domain.
    """

    if not domain or "." not in domain:
        return ""

    return "." + domain.rsplit(".", 1)[1].lower()


def has_suspicious_tld(domain):
    """
    Check whether the sender domain uses one of the
    suspicious TLDs configured for the MVP.
    """

    return get_tld(domain) in SUSPICIOUS_TLDS


# =========================================================
# FREE EMAIL PROVIDER DETECTION
# =========================================================

def is_free_email_provider(domain):
    """
    Check whether the sender uses a common free email provider.
    """

    return domain.lower() in FREE_EMAIL_PROVIDERS


# =========================================================
# IMPERSONATION DETECTION
# =========================================================

def detect_impersonation(domain):
    """
    Detect obvious organization impersonation patterns.

    Example:

        paypal-security-alert.xyz

    contains "paypal" but does not belong to paypal.com.
    """

    if not domain:
        return None

    domain_lower = domain.lower()

    # Extract the registrable-looking portion.
    # For the MVP we only need simple pattern detection.
    domain_without_tld = domain_lower.rsplit(".", 1)[0]

    for organization in KNOWN_ORGANIZATIONS:

        # Organization appears somewhere in the domain.
        if organization in domain_without_tld:

            # Expected official domain pattern.
            official_domain = f"{organization}.com"

            # Do not flag the obvious official domain itself.
            if domain_lower == official_domain:
                continue

            # Also don't flag a direct subdomain of the official
            # organization domain.
            if domain_lower.endswith("." + official_domain):
                continue

            return organization

    return None


# =========================================================
# SENDER ANALYZER
# =========================================================

def analyze_sender(sender):
    """
    Analyze the sender email address.

    Maximum sender contribution:
        25 points

    Returns:

    {
        "score": int,
        "domain": str,
        "findings": list
    }
    """

    sender = sender.strip() if isinstance(sender, str) else ""

    findings = []
    score = 0

    # -----------------------------------------------------
    # Validate email
    # -----------------------------------------------------

    if not is_valid_email(sender):

        findings.append({
            "indicator": "Invalid sender address",
            "severity": "MEDIUM",
            "description": (
                "The sender does not appear to use a valid email "
                "address format."
            ),
            "score_contribution": 8,
        })

        score += 8

        return {
            "score": min(score, 25),
            "domain": "",
            "findings": findings,
        }

    # -----------------------------------------------------
    # Extract domain
    # -----------------------------------------------------

    domain = extract_domain(sender)

    # -----------------------------------------------------
    # IP-based sender domain
    # -----------------------------------------------------

    if is_ip_address(domain):

        findings.append({
            "indicator": "IP address used as sender domain",
            "severity": "HIGH",
            "description": (
                "The sender uses an IP address instead of a conventional "
                "domain name."
            ),
            "score_contribution": 12,
        })

        score += 12

    # -----------------------------------------------------
    # Suspicious TLD
    # -----------------------------------------------------

    if has_suspicious_tld(domain):

        findings.append({
            "indicator": "Suspicious sender domain",
            "severity": "MEDIUM",
            "description": (
                f"The sender domain uses the {get_tld(domain)} "
                "top-level domain, which is treated as a warning "
                "signal by this MVP."
            ),
            "score_contribution": 7,
        })

        score += 7

    # -----------------------------------------------------
    # Impersonation detection
    # -----------------------------------------------------

    impersonated_org = detect_impersonation(domain)

    if impersonated_org:

        findings.append({
            "indicator": "Possible organization impersonation",
            "severity": "HIGH",
            "description": (
                f"The sender domain appears to reference "
                f"{impersonated_org.title()} but does not match "
                f"its expected official domain."
            ),
            "score_contribution": 10,
        })

        score += 10

    # -----------------------------------------------------
    # Free email provider
    # -----------------------------------------------------

    if is_free_email_provider(domain):

        findings.append({
            "indicator": "Free email provider",
            "severity": "LOW",
            "description": (
                "The sender uses a commonly available free email "
                "provider. This is a contextual warning signal and "
                "does not indicate maliciousness by itself."
            ),
            "score_contribution": 2,
        })

        score += 2

    # -----------------------------------------------------
    # Return result
    # -----------------------------------------------------

    return {
        "score": min(score, 25),
        "domain": domain,
        "findings": findings,
    }