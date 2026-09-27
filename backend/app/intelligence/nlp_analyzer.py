import re
from typing import Any


# ============================================================
# TRACE-AI NLP THREAT LANGUAGE ANALYZER
# ============================================================
#
# This module provides an explainable NLP-style signal layer.
#
# IMPORTANT:
# This is currently a deterministic linguistic analyzer,
# NOT a trained machine-learning model.
#
# It will later feed into the ML/evidence-fusion layer.
# ============================================================


# ============================================================
# URGENCY PATTERNS
# ============================================================

URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\basap\b",
    r"\baction required\b",
    r"\bact now\b",
    r"\bwithin\s+\d+\s+(?:minute|minutes|hour|hours)\b",
    r"\bdeadline\b",
    r"\bexpires?\b",
    r"\btoday\b",
    r"\bnow\b",
]


# ============================================================
# CREDENTIAL / ACCOUNT PATTERNS
# ============================================================

CREDENTIAL_PATTERNS = [
    r"\bpassword\b",
    r"\bpasscode\b",
    r"\bcredential[s]?\b",
    r"\bverify\s+(?:your\s+)?account\b",
    r"\bverify\s+(?:your\s+)?identity\b",
    r"\bverify\s+(?:your\s+)?password\b",
    r"\bconfirm\s+(?:your\s+)?account\b",
    r"\bconfirm\s+(?:your\s+)?identity\b",
    r"\blogin\b",
    r"\blog\s*in\b",
    r"\bsign\s*in\b",
    r"\busername\b",
    r"\bsecurity\s+code\b",
    r"\bsecurity\s+credentials\b",
]


# ============================================================
# FEAR / THREAT PATTERNS
# ============================================================

FEAR_PATTERNS = [
    r"\bsuspended\b",
    r"\bsuspension\b",
    r"\bdeactivated\b",
    r"\bdeactivation\b",
    r"\blocked\b",
    r"\bterminated\b",
    r"\bunauthorized\b",
    r"\bsecurity\s+alert\b",
    r"\bsecurity\s+threat\b",
    r"\baccount\s+will\s+be\b",
    r"\baccess\s+will\s+be\b",
    r"\bpermanent\s+suspension\b",
    r"\bpermanent\s+loss\b",
    r"\blose\s+access\b",
]


# ============================================================
# FINANCIAL PATTERNS
# ============================================================

FINANCIAL_PATTERNS = [
    r"\bpayment\b",
    r"\binvoice\b",
    r"\bwire\s+transfer\b",
    r"\bbank\s+account\b",
    r"\btransaction\b",
    r"\brefund\b",
    r"\btransfer\b",
    r"\bpay\b",
    r"\bpayment\s+details\b",
    r"\bcredit\s+card\b",
    r"\bdebit\s+card\b",
    r"\bbilling\b",
    r"\bmoney\b",
    r"\bfinancial\b",
]


# ============================================================
# AUTHORITY / IMPERSONATION PATTERNS
# ============================================================

AUTHORITY_PATTERNS = [
    r"\bceo\b",
    r"\bcfo\b",
    r"\bchief\s+executive\b",
    r"\bmanager\b",
    r"\bdirector\b",
    r"\badministrator\b",
    r"\bit\s+department\b",
    r"\bit\s+administrator\b",
    r"\bsecurity\s+team\b",
    r"\bsecurity\s+department\b",
    r"\bhuman\s+resources\b",
    r"\bhr\s+department\b",
    r"\btechnical\s+support\b",
    r"\bsupport\s+team\b",
    r"\baccount\s+administrator\b",
    r"\bmicrosoft\s+security\b",
    r"\bgoogle\s+security\b",
    r"\bapple\s+support\b",
]


# ============================================================
# SECRECY PATTERNS
# ============================================================

SECRECY_PATTERNS = [
    r"\bconfidential\b",
    r"\bdo\s+not\s+share\b",
    r"\bkeep\s+this\s+private\b",
    r"\bsecret\b",
    r"\bdo\s+not\s+tell\b",
    r"\bbetween\s+us\b",
    r"\bdo\s+not\s+disclose\b",
    r"\bkeep\s+this\s+confidential\b",
]


# ============================================================
# CALL-TO-ACTION PATTERNS
# ============================================================

CALL_TO_ACTION_PATTERNS = [
    r"\bclick\s+here\b",
    r"\bclick\s+the\s+link\b",
    r"\bclick\s+below\b",
    r"\bclick\s+this\s+link\b",
    r"\bopen\s+the\s+link\b",
    r"\bopen\s+the\s+portal\b",
    r"\bvisit\s+the\s+link\b",
    r"\buse\s+the\s+secure\s+portal\b",
    r"\buse\s+the\s+portal\b",
    r"\bverify\s+now\b",
    r"\bverify\s+(?:your\s+)?account\b",
    r"\bverify\s+(?:your\s+)?password\b",
    r"\bconfirm\s+now\b",
    r"\bconfirm\s+(?:your\s+)?account\b",
    r"\bupdate\s+(?:your\s+)?account\b",
    r"\bupdate\s+(?:your\s+)?information\b",
    r"\blog\s*in\s+now\b",
    r"\bsign\s+in\s+now\b",
    r"\btake\s+action\b",
    r"\bcomplete\s+(?:the\s+)?verification\b",
    r"\bcomplete\s+(?:the\s+)?process\b",
    r"\bclick\s+to\s+verify\b",
]


# ============================================================
# SUSPICIOUS DOWNLOAD PATTERNS
# ============================================================

DOWNLOAD_PATTERNS = [
    r"\bdownload\b",
    r"\bopen\s+the\s+attachment\b",
    r"\bopen\s+attachment\b",
    r"\bsee\s+attached\b",
    r"\bview\s+attachment\b",
    r"\binstall\b",
    r"\bupdate\s+your\s+software\b",
    r"\bsecurity\s+update\b",
]


# ============================================================
# PATTERN MATCHING
# ============================================================

def find_matches(
    text: str,
    patterns: list[str]
) -> list[str]:

    matches = []

    if not text:
        return matches

    for pattern in patterns:

        found = re.findall(
            pattern,
            text,
            flags=re.IGNORECASE
        )

        for match in found:

            if isinstance(
                match,
                tuple
            ):

                value = " ".join(
                    str(item)
                    for item in match
                    if item
                )

            else:

                value = str(match)

            value = value.strip()

            if (
                value
                and value.lower()
                not in [
                    item.lower()
                    for item in matches
                ]
            ):

                matches.append(
                    value
                )

    return matches


# ============================================================
# CATEGORY ANALYSIS
# ============================================================

def analyze_category(
    text: str,
    patterns: list[str],
    name: str
) -> dict[str, Any]:

    matches = find_matches(
        text,
        patterns
    )

    return {
        "category": name,
        "detected": bool(matches),
        "match_count": len(matches),
        "matches": matches
    }


# ============================================================
# SUSPICIOUS TEXT SEGMENTS
# ============================================================

def extract_suspicious_segments(
    text: str
) -> list[dict[str, Any]]:

    segments = []

    if not text:
        return segments

    # --------------------------------------------------------
    # Split text into approximate sentences/lines.
    # --------------------------------------------------------

    sentences = re.split(
        r"(?<=[.!?])\s+|\n+",
        text
    )

    for sentence in sentences:

        sentence = sentence.strip()

        if not sentence:
            continue

        categories = []

        if find_matches(
            sentence,
            URGENCY_PATTERNS
        ):
            categories.append(
                "URGENCY"
            )

        if find_matches(
            sentence,
            CREDENTIAL_PATTERNS
        ):
            categories.append(
                "CREDENTIAL_REQUEST"
            )

        if find_matches(
            sentence,
            FEAR_PATTERNS
        ):
            categories.append(
                "FEAR / THREAT"
            )

        if find_matches(
            sentence,
            FINANCIAL_PATTERNS
        ):
            categories.append(
                "FINANCIAL_PRESSURE"
            )

        if find_matches(
            sentence,
            AUTHORITY_PATTERNS
        ):
            categories.append(
                "AUTHORITY / IMPERSONATION"
            )

        if find_matches(
            sentence,
            SECRECY_PATTERNS
        ):
            categories.append(
                "SECRECY"
            )

        if find_matches(
            sentence,
            CALL_TO_ACTION_PATTERNS
        ):
            categories.append(
                "CALL TO ACTION"
            )

        if find_matches(
            sentence,
            DOWNLOAD_PATTERNS
        ):
            categories.append(
                "DOWNLOAD / INSTALLATION"
            )

        if categories:

            segments.append({
                "text": sentence,
                "signals": categories
            })

    return segments


# ============================================================
# NLP RISK SCORE
# ============================================================

def calculate_nlp_score(
    categories: dict[str, dict]
) -> int:

    score = 0

    # --------------------------------------------------------
    # Urgency
    # --------------------------------------------------------

    if categories[
        "urgency"
    ]["detected"]:

        score += 20

    # --------------------------------------------------------
    # Credential request
    # --------------------------------------------------------

    if categories[
        "credential_request"
    ]["detected"]:

        score += 25

    # --------------------------------------------------------
    # Fear / threat
    # --------------------------------------------------------

    if categories[
        "fear_or_threat"
    ]["detected"]:

        score += 15

    # --------------------------------------------------------
    # Financial pressure
    # --------------------------------------------------------

    if categories[
        "financial_pressure"
    ]["detected"]:

        score += 20

    # --------------------------------------------------------
    # Authority / impersonation
    # --------------------------------------------------------

    if categories[
        "authority_or_impersonation"
    ]["detected"]:

        score += 10

    # --------------------------------------------------------
    # Secrecy
    # --------------------------------------------------------

    if categories[
        "secrecy"
    ]["detected"]:

        score += 5

    # --------------------------------------------------------
    # Call to action
    # --------------------------------------------------------

    if categories[
        "call_to_action"
    ]["detected"]:

        score += 5

    # --------------------------------------------------------
    # Download / installation
    # --------------------------------------------------------

    if categories[
        "download_or_installation"
    ]["detected"]:

        score += 5

    return min(
        score,
        100
    )


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_nlp_risk(
    score: int
) -> str:

    if score >= 70:

        return "HIGH"

    if score >= 40:

        return "MEDIUM"

    return "LOW"


# ============================================================
# THREAT CATEGORY DETECTION
# ============================================================

def determine_threat_categories(
    categories: dict[str, dict]
) -> list[str]:

    threat_categories = []

    # --------------------------------------------------------
    # Credential phishing
    # --------------------------------------------------------

    if (
        categories[
            "credential_request"
        ]["detected"]
        and
        (
            categories[
                "urgency"
            ]["detected"]
            or
            categories[
                "fear_or_threat"
            ]["detected"]
            or
            categories[
                "call_to_action"
            ]["detected"]
        )
    ):

        threat_categories.append(
            "Credential Phishing"
        )

    # --------------------------------------------------------
    # BEC
    # --------------------------------------------------------

    if (
        categories[
            "authority_or_impersonation"
        ]["detected"]
        and
        categories[
            "financial_pressure"
        ]["detected"]
    ):

        threat_categories.append(
            "Potential BEC"
        )

    # --------------------------------------------------------
    # Impersonation
    # --------------------------------------------------------

    if categories[
        "authority_or_impersonation"
    ]["detected"]:

        threat_categories.append(
            "Impersonation"
        )

    # --------------------------------------------------------
    # Social engineering
    # --------------------------------------------------------

    social_engineering_signals = 0

    for category_name in [
        "urgency",
        "fear_or_threat",
        "authority_or_impersonation",
        "call_to_action",
        "credential_request"
    ]:

        if categories[
            category_name
        ]["detected"]:

            social_engineering_signals += 1

    if social_engineering_signals >= 2:

        threat_categories.append(
            "Social Engineering"
        )

    # --------------------------------------------------------
    # Malicious download / installation
    # --------------------------------------------------------

    if categories[
        "download_or_installation"
    ]["detected"]:

        threat_categories.append(
            "Potential Malicious Download"
        )

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------

    return list(
        dict.fromkeys(
            threat_categories
        )
    )


# ============================================================
# HUMAN-READABLE REASONS
# ============================================================

def build_reasons(
    categories: dict[str, dict]
) -> list[str]:

    reasons = []

    if categories[
        "urgency"
    ]["detected"]:

        reasons.append(
            "Urgency or time pressure detected"
        )

    if categories[
        "credential_request"
    ]["detected"]:

        reasons.append(
            "Credential or account verification language detected"
        )

    if categories[
        "fear_or_threat"
    ]["detected"]:

        reasons.append(
            "Fear or account-threat language detected"
        )

    if categories[
        "financial_pressure"
    ]["detected"]:

        reasons.append(
            "Financial or payment-related language detected"
        )

    if categories[
        "authority_or_impersonation"
    ]["detected"]:

        reasons.append(
            "Authority or impersonation language detected"
        )

    if categories[
        "secrecy"
    ]["detected"]:

        reasons.append(
            "Secrecy or confidentiality language detected"
        )

    if categories[
        "call_to_action"
    ]["detected"]:

        reasons.append(
            "Suspicious call-to-action language detected"
        )

    if categories[
        "download_or_installation"
    ]["detected"]:

        reasons.append(
            "Download or installation language detected"
        )

    return reasons


# ============================================================
# MAIN NLP ANALYZER
# ============================================================

def analyze_email_language(
    subject: str = "",
    body: str = "",
    sender: str = ""
) -> dict[str, Any]:

    # --------------------------------------------------------
    # Combine relevant text
    # --------------------------------------------------------

    text = (
        f"Subject: {subject}\n"
        f"From: {sender}\n"
        f"{body}"
    )

    # --------------------------------------------------------
    # Analyze categories
    # --------------------------------------------------------

    categories = {

        "urgency": analyze_category(
            text,
            URGENCY_PATTERNS,
            "Urgency"
        ),

        "credential_request": analyze_category(
            text,
            CREDENTIAL_PATTERNS,
            "Credential Request"
        ),

        "fear_or_threat": analyze_category(
            text,
            FEAR_PATTERNS,
            "Fear / Threat"
        ),

        "financial_pressure": analyze_category(
            text,
            FINANCIAL_PATTERNS,
            "Financial Pressure"
        ),

        "authority_or_impersonation": analyze_category(
            text,
            AUTHORITY_PATTERNS,
            "Authority / Impersonation"
        ),

        "secrecy": analyze_category(
            text,
            SECRECY_PATTERNS,
            "Secrecy"
        ),

        "call_to_action": analyze_category(
            text,
            CALL_TO_ACTION_PATTERNS,
            "Call to Action"
        ),

        "download_or_installation": analyze_category(
            text,
            DOWNLOAD_PATTERNS,
            "Download / Installation"
        )
    }

    # --------------------------------------------------------
    # NLP score
    # --------------------------------------------------------

    nlp_score = calculate_nlp_score(
        categories
    )

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    risk_level = classify_nlp_risk(
        nlp_score
    )

    # --------------------------------------------------------
    # Threat categories
    # --------------------------------------------------------

    threat_categories = (
        determine_threat_categories(
            categories
        )
    )

    # --------------------------------------------------------
    # Suspicious segments
    # --------------------------------------------------------

    suspicious_segments = (
        extract_suspicious_segments(
            text
        )
    )

    # --------------------------------------------------------
    # Human-readable explanations
    # --------------------------------------------------------

    reasons = build_reasons(
        categories
    )

    # --------------------------------------------------------
    # Return result
    # --------------------------------------------------------

    return {

        "engine": (
            "TRACE-AI NLP "
            "Threat Language Analyzer"
        ),

        "analysis_type": (
            "Explainable linguistic "
            "signal analysis"
        ),

        "nlp_score": nlp_score,

        "risk_level": risk_level,

        "threat_categories": (
            threat_categories
        ),

        "categories": categories,

        "reasons": reasons,

        "suspicious_segments": (
            suspicious_segments
        )
    }