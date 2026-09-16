import re


# =========================================================
# CONTENT INDICATORS
# =========================================================

CONTENT_INDICATORS = {

    "urgency": {
        "patterns": [
            r"\burgent\b",
            r"\bimmediately\b",
            r"\bact now\b",
            r"\bfinal warning\b",
            r"\bwithin 24 hours\b",
        ],
        "indicator": "Urgency language",
        "severity": "MEDIUM",
        "description": (
            "The email attempts to create pressure by demanding "
            "immediate action."
        ),
        "score": 8,
    },

    "credential_request": {
        "patterns": [
            r"\bpassword\b",
            r"\bverify your account\b",
            r"\bconfirm your credentials\b",
            r"\blogin\b",
            r"\blog in\b",
            r"\breset your password\b",
        ],
        "indicator": "Credential request",
        "severity": "HIGH",
        "description": (
            "The email requests or references account credentials "
            "or login information."
        ),
        "score": 15,
    },

    "financial_request": {
        "patterns": [
            r"\bpayment\b",
            r"\bbank account\b",
            r"\bwire transfer\b",
            r"\bgift card\b",
            r"\bcryptocurrency\b",
            r"\bcrypto currency\b",
        ],
        "indicator": "Financial request",
        "severity": "HIGH",
        "description": (
            "The email contains language associated with financial "
            "transactions or requests."
        ),
        "score": 12,
    },

    "threat_language": {
        "patterns": [
            r"\baccount suspended\b",
            r"\baccount closed\b",
            r"\blegal action\b",
            r"\bunauthorized activity\b",
        ],
        "indicator": "Threat language",
        "severity": "HIGH",
        "description": (
            "The email uses consequences, account restrictions, "
            "or threatening language to influence the recipient."
        ),
        "score": 12,
    },
}


# =========================================================
# TEXT NORMALIZATION
# =========================================================

def normalize_text(text):
    """
    Normalize email text for consistent rule matching.
    """

    if not isinstance(text, str):
        return ""

    # Convert HTML-like content into spaces where possible.
    text = re.sub(r"<[^>]+>", " ", text)

    # Normalize whitespace.
    text = re.sub(r"\s+", " ", text)

    return text.strip().lower()


# =========================================================
# PATTERN MATCHING
# =========================================================

def pattern_found(text, patterns):
    """
    Check whether at least one pattern from a list
    appears in the supplied text.

    Returns:
        bool
    """

    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True

    return False


# =========================================================
# CONTENT ANALYZER
# =========================================================

def analyze_content(subject, body):
    """
    Analyze the subject and body of an email for
    common phishing/threat indicators.

    Returns:

    {
        "score": int,
        "findings": list
    }

    The content score is capped at 40 because the MVP
    allocates a maximum of 40 points to content analysis.
    """

    subject = normalize_text(subject)
    body = normalize_text(body)

    combined_text = f"{subject} {body}".strip()

    findings = []
    total_score = 0

    # -----------------------------------------------------
    # Check every content indicator
    # -----------------------------------------------------

    for indicator_data in CONTENT_INDICATORS.values():

        if pattern_found(
            combined_text,
            indicator_data["patterns"]
        ):

            finding = {
                "indicator": indicator_data["indicator"],
                "severity": indicator_data["severity"],
                "description": indicator_data["description"],
                "score_contribution": indicator_data["score"],
            }

            findings.append(finding)

            total_score += indicator_data["score"]

    # -----------------------------------------------------
    # Cap content score at 40
    # -----------------------------------------------------

    total_score = min(total_score, 40)

    # -----------------------------------------------------
    # Return result
    # -----------------------------------------------------

    return {
        "score": total_score,
        "findings": findings,
    }