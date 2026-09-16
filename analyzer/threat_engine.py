from analyzer.content_analyzer import analyze_content
from analyzer.sender_analyzer import analyze_sender
from analyzer.url_analyzer import analyze_urls
from analyzer.risk_scorer import assess_risk


# =========================================================
# NEON GUARD - THREAT ENGINE
# =========================================================


def build_threat_indicators(
    content_result,
    sender_result,
    url_result
):
    """
    Combine findings from all analyzers into one list.

    Each finding is tagged with its source so the frontend
    can understand where the signal came from.
    """

    indicators = []

    # -----------------------------------------------------
    # Content findings
    # -----------------------------------------------------

    for finding in content_result.get("findings", []):

        indicators.append({
            "source": "CONTENT",
            "indicator": finding.get("indicator", "Unknown"),
            "severity": finding.get("severity", "LOW"),
            "description": finding.get("description", ""),
            "score_contribution": finding.get(
                "score_contribution",
                0
            ),
        })

    # -----------------------------------------------------
    # Sender findings
    # -----------------------------------------------------

    for finding in sender_result.get("findings", []):

        indicators.append({
            "source": "SENDER",
            "indicator": finding.get("indicator", "Unknown"),
            "severity": finding.get("severity", "LOW"),
            "description": finding.get("description", ""),
            "score_contribution": finding.get(
                "score_contribution",
                0
            ),
        })

    # -----------------------------------------------------
    # URL findings
    # -----------------------------------------------------

    for finding in url_result.get("findings", []):

        indicators.append({
            "source": "URL",
            "indicator": finding.get("indicator", "Unknown"),
            "severity": finding.get("severity", "LOW"),
            "description": finding.get("description", ""),
            "score_contribution": finding.get(
                "score_contribution",
                0
            ),
        })

    return indicators


# =========================================================
# EXPLANATION GENERATOR
# =========================================================

def build_explanation(
    risk_score,
    risk_level,
    threat_indicators
):
    """
    Generate a short explanation based only on the
    findings actually detected by the analyzers.
    """

    explanation = []

    # -----------------------------------------------------
    # Overall assessment
    # -----------------------------------------------------

    if risk_score < 20:

        explanation.append(
            "The email shows few characteristics associated "
            "with common phishing threats."
        )

    elif risk_score < 40:

        explanation.append(
            "The email contains some warning signals that "
            "warrant additional caution."
        )

    elif risk_score < 60:

        explanation.append(
            "The email contains several characteristics "
            "commonly associated with suspicious messages."
        )

    elif risk_score < 80:

        explanation.append(
            "The email shows multiple characteristics "
            "commonly associated with phishing or other "
            "suspicious activity."
        )

    else:

        explanation.append(
            "The email shows several strong characteristics "
            "commonly associated with phishing."
        )

    # -----------------------------------------------------
    # Track categories already mentioned
    # -----------------------------------------------------

    mentioned_sources = set()

    # -----------------------------------------------------
    # Explain actual findings
    # -----------------------------------------------------

    for finding in threat_indicators:

        source = finding.get("source")
        description = finding.get("description")

        if not description:
            continue

        # Avoid repeating multiple descriptions from the
        # same broad category when the list gets long.
        if source in mentioned_sources:
            continue

        explanation.append(description)
        mentioned_sources.add(source)

        # Keep the explanation concise.
        if len(explanation) >= 4:
            break

    return explanation


# =========================================================
# RECOMMENDATIONS
# =========================================================

def build_recommendations(
    risk_score,
    threat_indicators
):
    """
    Generate recommendations based on the actual
    detected risk signals.
    """

    recommendations = []

    indicator_names = {
        finding.get("indicator", "").lower()
        for finding in threat_indicators
    }

    # -----------------------------------------------------
    # URL-related recommendation
    # -----------------------------------------------------

    url_related = any(
        finding.get("source") == "URL"
        for finding in threat_indicators
    )

    if url_related:
        recommendations.append(
            "Do not click suspicious links in the email."
        )

    # -----------------------------------------------------
    # Credential-related recommendation
    # -----------------------------------------------------

    credential_related = any(
        "credential" in name
        or "password" in name
        or "login" in name
        for name in indicator_names
    )

    if credential_related:
        recommendations.append(
            "Do not provide passwords or account credentials "
            "through links contained in the email."
        )

    # -----------------------------------------------------
    # Sender-related recommendation
    # -----------------------------------------------------

    sender_related = any(
        finding.get("source") == "SENDER"
        for finding in threat_indicators
    )

    if sender_related:
        recommendations.append(
            "Verify the sender and domain through a trusted "
            "channel before taking action."
        )

    # -----------------------------------------------------
    # High-risk recommendation
    # -----------------------------------------------------

    if risk_score >= 60:
        recommendations.append(
            "Treat the message with caution and verify the "
            "request independently."
        )

    # -----------------------------------------------------
    # Generic safe recommendation
    # -----------------------------------------------------

    if not recommendations:
        recommendations.append(
            "No immediate high-risk indicators were detected, "
            "but continue to use normal email security practices."
        )

    return recommendations


# =========================================================
# SIGNAL SUMMARY
# =========================================================

def build_signal_summary(
    content_result,
    sender_result,
    url_result
):
    """
    Build a compact signal summary for the frontend.
    """

    return {
        "content": {
            "score": content_result.get("score", 0),
            "max_score": 40,
            "findings": content_result.get("findings", []),
        },

        "sender": {
            "score": sender_result.get("score", 0),
            "max_score": 25,
            "domain": sender_result.get("domain", ""),
            "findings": sender_result.get("findings", []),
        },

        "urls": {
            "score": url_result.get("score", 0),
            "max_score": 35,
            "count": len(url_result.get("urls", [])),
            "items": url_result.get("urls", []),
            "findings": url_result.get("findings", []),
        },
    }


# =========================================================
# MAIN THREAT ENGINE
# =========================================================

def analyze_email(sender, subject, body):
    """
    Main NEON GUARD analysis function.

    Pipeline:

        Email
          ↓
        Content Analyzer
          ↓
        Sender Analyzer
          ↓
        URL Analyzer
          ↓
        Risk Scorer
          ↓
        Final Assessment

    Returns the complete JSON-compatible result.
    """

    # -----------------------------------------------------
    # 1. Analyze content
    # -----------------------------------------------------

    content_result = analyze_content(
        subject=subject,
        body=body
    )

    # -----------------------------------------------------
    # 2. Analyze sender
    # -----------------------------------------------------

    sender_result = analyze_sender(
        sender=sender
    )

    # -----------------------------------------------------
    # 3. Analyze URLs
    # -----------------------------------------------------

    # Analyze URLs from the email body.
    url_result = analyze_urls(
        text=body
    )

    # -----------------------------------------------------
    # 4. Combine all threat indicators
    # -----------------------------------------------------

    threat_indicators = build_threat_indicators(
        content_result=content_result,
        sender_result=sender_result,
        url_result=url_result
    )

    # -----------------------------------------------------
    # 5. Calculate final risk
    # -----------------------------------------------------

    risk_assessment = assess_risk(
        content_score=content_result.get("score", 0),
        sender_score=sender_result.get("score", 0),
        url_score=url_result.get("score", 0),
        threat_indicators=threat_indicators
    )

    risk_score = risk_assessment["risk_score"]
    risk_level = risk_assessment["risk_level"]
    classification = risk_assessment["classification"]

    # -----------------------------------------------------
    # 6. Generate explanation
    # -----------------------------------------------------

    explanation = build_explanation(
        risk_score=risk_score,
        risk_level=risk_level,
        threat_indicators=threat_indicators
    )

    # -----------------------------------------------------
    # 7. Generate recommendations
    # -----------------------------------------------------

    recommendations = build_recommendations(
        risk_score=risk_score,
        threat_indicators=threat_indicators
    )

    # -----------------------------------------------------
    # 8. Build signal summary
    # -----------------------------------------------------

    signals = build_signal_summary(
        content_result=content_result,
        sender_result=sender_result,
        url_result=url_result
    )

    # -----------------------------------------------------
    # 9. Return final assessment
    # -----------------------------------------------------

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "classification": classification,

        "signals": signals,

        "threat_indicators": threat_indicators,

        "explanation": explanation,

        "recommendations": recommendations,
    }