from __future__ import annotations


def calculate_risk_score(
    features: dict,
    lookalike_analysis: dict | None = None
) -> dict:
    """
    Calculate an explainable threat score.

    Current implementation:
    - Deterministic forensic signals
    - Content/social-engineering signals
    - URL/attachment signals
    - Lookalike-domain intelligence

    This is an MVP engineering baseline.
    The weights are not statistically validated.
    """

    score = 0
    evidence = []

    # ==================================================
    # AUTHENTICATION SIGNALS
    # ==================================================

    if features.get("spf_fail", 0):
        score += 15
        evidence.append(
            "SPF authentication failed"
        )

    if features.get("dkim_fail", 0):
        score += 10
        evidence.append(
            "DKIM authentication failed"
        )

    if features.get("dmarc_fail", 0):
        score += 15
        evidence.append(
            "DMARC authentication failed"
        )

    # ==================================================
    # CONTENT / SOCIAL ENGINEERING
    # ==================================================

    urgency_count = features.get(
        "urgency_count",
        0
    )

    if urgency_count > 0:
        points = min(
            10,
            urgency_count * 2
        )

        score += points

        evidence.append(
            f"Urgency language detected "
            f"({urgency_count} signals)"
        )

    credential_count = features.get(
        "credential_request_count",
        0
    )

    if credential_count > 0:
        points = min(
            15,
            credential_count * 5
        )

        score += points

        evidence.append(
            f"Credential request detected "
            f"({credential_count} signals)"
        )

    threat_count = features.get(
        "threat_language_count",
        0
    )

    if threat_count > 0:
        points = min(
            10,
            threat_count * 3
        )

        score += points

        evidence.append(
            f"Threat language detected "
            f"({threat_count} signals)"
        )

    # ==================================================
    # URL SIGNALS
    # ==================================================

    url_count = features.get(
        "url_count",
        0
    )

    if url_count > 0:
        score += 5

        evidence.append(
            f"URL detected ({url_count})"
        )

    # ==================================================
    # ATTACHMENT SIGNALS
    # ==================================================

    executable_count = features.get(
        "executable_attachment_count",
        0
    )

    if executable_count > 0:

        points = min(
            15,
            executable_count * 15
        )

        score += points

        evidence.append(
            f"Executable attachment detected "
            f"({executable_count})"
        )

    # ==================================================
    # LOOKALIKE DOMAIN INTELLIGENCE
    # ==================================================

    if lookalike_analysis:

        is_lookalike = (
            lookalike_analysis.get(
                "is_lookalike",
                False
            )
        )

        if is_lookalike:

            # Strong domain impersonation signal
            score += 15

            matched_brand = (
                lookalike_analysis.get(
                    "matched_brand"
                )
                or "known brand"
            )

            similarity = (
                lookalike_analysis.get(
                    "similarity",
                    0
                )
            )

            evidence.append(
                f"Lookalike domain detected "
                f"(possible {matched_brand} impersonation, "
                f"{similarity}% similarity)"
            )

            # Character substitution
            if lookalike_analysis.get(
                "substitution_detected",
                False
            ):

                matched_token = (
                    lookalike_analysis.get(
                        "matched_token"
                    )
                    or "domain token"
                )

                evidence.append(
                    f"Character substitution detected "
                    f"in '{matched_token}'"
                )

            # Suspicious domain tokens
            suspicious_tokens = (
                lookalike_analysis.get(
                    "suspicious_tokens",
                    []
                )
            )

            if suspicious_tokens:

                tokens = ", ".join(
                    suspicious_tokens
                )

                evidence.append(
                    f"Suspicious domain token(s): "
                    f"{tokens}"
                )

            # Punycode
            if lookalike_analysis.get(
                "punycode_detected",
                False
            ):

                evidence.append(
                    "Punycode domain detected"
                )

    # ==================================================
    # SMTP / INFRASTRUCTURE
    # ==================================================

    received_hops = features.get(
        "received_hop_count",
        0
    )

    if received_hops > 0:

        evidence.append(
            f"SMTP relay path contains "
            f"{received_hops} visible hop(s)"
        )

    # ==================================================
    # CAP SCORE
    # ==================================================

    score = min(
        score,
        100
    )

    # ==================================================
    # RISK LEVEL
    # ==================================================

    if score >= 70:
        risk_level = "HIGH"

    elif score >= 40:
        risk_level = "MEDIUM"

    elif score >= 20:
        risk_level = "LOW"

    else:
        risk_level = "MINIMAL"

    # ==================================================
    # CLASSIFICATION
    # ==================================================

    if score >= 70:

        if credential_count > 0:

            classification = "PHISHING"

        elif executable_count > 0:

            classification = "MALWARE DELIVERY"

        else:

            classification = "SUSPICIOUS EMAIL"

    elif score >= 40:

        classification = "SUSPICIOUS EMAIL"

    else:

        classification = "LIKELY LEGITIMATE"

    # ==================================================
    # RETURN
    # ==================================================

    return {
        "threat_score": score,
        "risk_level": risk_level,
        "classification": classification,
        "evidence": evidence
    }