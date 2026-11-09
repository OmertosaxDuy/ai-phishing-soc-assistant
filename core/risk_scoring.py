from core.detection_rules import detect_phishing


def calculate_risk_score(findings):
    """
    Calculate total risk score from detection findings.

    The score is capped at 100.
    """
    total_score = 0

    for finding in findings:
        score = finding.get("score", 0)

        if isinstance(score, (int, float)) and not isinstance(score, bool):
            total_score += max(0, score)

    return min(100, total_score)


def classify_risk(score):
    """
    Classify the risk level based on score.
    """
    if score >= 70:
        return "High"

    elif score >= 35:
        return "Medium"

    return "Low"


def assess_email_risk(email_data):
    """
    Run detection rules and calculate
    the overall email risk assessment.
    """
    findings = detect_phishing(email_data)

    risk_score = calculate_risk_score(findings)
    risk_level = classify_risk(risk_score)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_findings": len(findings),
        "findings": findings
    }
