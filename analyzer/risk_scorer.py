# =========================================================
# NEON GUARD - RISK SCORER
# =========================================================


# Maximum score contributed by each analyzer.
CONTENT_MAX_SCORE = 40
SENDER_MAX_SCORE = 25
URL_MAX_SCORE = 35

TOTAL_MAX_SCORE = 100


# =========================================================
# SCORE CLAMPING
# =========================================================

def clamp_score(score, minimum=0, maximum=100):
    """
    Keep a score within the specified range.

    This protects the final risk score from accidentally
    going below 0 or above 100.
    """

    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0

    return max(minimum, min(score, maximum))


# =========================================================
# RISK LEVEL
# =========================================================

def get_risk_level(score):
    """
    Convert a numerical risk score into a risk level.

    0–19     SAFE
    20–39    LOW RISK
    40–59    SUSPICIOUS
    60–79    HIGH RISK
    80–100   CRITICAL
    """

    score = clamp_score(score)

    if score <= 19:
        return "SAFE"

    if score <= 39:
        return "LOW RISK"

    if score <= 59:
        return "SUSPICIOUS"

    if score <= 79:
        return "HIGH RISK"

    return "CRITICAL"


# =========================================================
# CLASSIFICATION
# =========================================================

def get_classification(score, threat_indicators=None):
    """
    Determine the broad email classification.

    Classifications:
        SAFE
        SUSPICIOUS
        LIKELY PHISHING

    The classification is intentionally conservative.
    A high score indicates risk signals, not certainty.
    """

    score = clamp_score(score)

    if threat_indicators is None:
        threat_indicators = []

    # -----------------------------------------------------
    # Safe range
    # -----------------------------------------------------

    if score < 20:
        return "SAFE"

    # -----------------------------------------------------
    # Higher-risk messages with actual indicators
    # -----------------------------------------------------

    if score >= 60 and len(threat_indicators) > 0:
        return "LIKELY PHISHING"

    # -----------------------------------------------------
    # Everything else with meaningful warning signals
    # -----------------------------------------------------

    return "SUSPICIOUS"


# =========================================================
# RISK SCORE CALCULATION
# =========================================================

def calculate_risk_score(
    content_score,
    sender_score,
    url_score
):
    """
    Calculate the final risk score.

    Maximum contributions:

        Content = 40
        Sender  = 25
        URLs    = 35

        Total   = 100

    The calculation is deterministic.
    """

    # -----------------------------------------------------
    # Clamp individual analyzer scores
    # -----------------------------------------------------

    content_score = clamp_score(
        content_score,
        0,
        CONTENT_MAX_SCORE
    )

    sender_score = clamp_score(
        sender_score,
        0,
        SENDER_MAX_SCORE
    )

    url_score = clamp_score(
        url_score,
        0,
        URL_MAX_SCORE
    )

    # -----------------------------------------------------
    # Combine scores
    # -----------------------------------------------------

    total_score = (
        content_score
        + sender_score
        + url_score
    )

    # Final safety clamp.
    total_score = clamp_score(
        total_score,
        0,
        TOTAL_MAX_SCORE
    )

    return total_score


# =========================================================
# COMPLETE RISK ASSESSMENT
# =========================================================

def assess_risk(
    content_score,
    sender_score,
    url_score,
    threat_indicators=None
):
    """
    Produce the complete risk assessment.

    Returns:

    {
        "risk_score": 0-100,
        "risk_level": "...",
        "classification": "..."
    }
    """

    risk_score = calculate_risk_score(
        content_score=content_score,
        sender_score=sender_score,
        url_score=url_score
    )

    risk_level = get_risk_level(risk_score)

    classification = get_classification(
        score=risk_score,
        threat_indicators=threat_indicators
    )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "classification": classification,
    }