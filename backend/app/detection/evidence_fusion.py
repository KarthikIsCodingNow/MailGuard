from typing import Any

from app.ml.integration import build_ml_evidence


# ============================================================
# TRACE-AI EVIDENCE FUSION ENGINE
# ============================================================
#
# Combines independent evidence sources into one
# explainable threat assessment.
#
# Evidence sources:
#   1. Forensics
#   2. NLP
#   3. Lookalike domains
#   4. SPF / DKIM / DMARC
#   5. URLs
#   6. Attachments
#   7. Neo4j graph correlation
#   8. Machine Learning
#
# IMPORTANT:
# The final score is an engineering assessment score.
# It is NOT a calibrated probability.
#
# ML is used as supporting evidence.
# It is NOT treated as an independent evidence family
# because its features are derived from existing evidence.
# ============================================================


# ============================================================
# HELPERS
# ============================================================

def clamp(
    value: float,
    minimum: float = 0,
    maximum: float = 100
) -> float:

    return max(
        minimum,
        min(
            maximum,
            value
        )
    )


def safe_int(
    value: Any,
    default: int = 0
) -> int:

    try:
        return int(value)

    except (
        TypeError,
        ValueError
    ):
        return default


# ============================================================
# FORENSIC EVIDENCE
# ============================================================

def analyze_forensic_evidence(
    risk_assessment: dict
) -> dict:

    threat_score = safe_int(
        risk_assessment.get(
            "threat_score",
            0
        )
    )

    evidence = risk_assessment.get(
        "evidence",
        []
    )

    if not isinstance(
        evidence,
        list
    ):
        evidence = []

    return {

        "score": clamp(
            threat_score
        ),

        "evidence_count": len(
            evidence
        ),

        "evidence": evidence
    }


# ============================================================
# NLP EVIDENCE
# ============================================================

def analyze_nlp_evidence(
    nlp_analysis: dict
) -> dict:

    nlp_score = safe_int(
        nlp_analysis.get(
            "nlp_score",
            0
        )
    )

    risk_level = str(
        nlp_analysis.get(
            "risk_level",
            "LOW"
        )
    ).upper()

    categories = nlp_analysis.get(
        "categories",
        {}
    )

    reasons = nlp_analysis.get(
        "reasons",
        []
    )

    threat_categories = (
        nlp_analysis.get(
            "threat_categories",
            []
        )
    )

    detected_categories = []

    if isinstance(
        categories,
        dict
    ):

        for key, value in categories.items():

            if (
                isinstance(
                    value,
                    dict
                )
                and value.get(
                    "detected"
                )
            ):

                detected_categories.append(
                    key
                )

    return {

        "score": clamp(
            nlp_score
        ),

        "risk_level": risk_level,

        "detected_categories": (
            detected_categories
        ),

        "threat_categories": (
            threat_categories
        ),

        "reasons": (
            reasons
            if isinstance(
                reasons,
                list
            )
            else []
        )
    }


# ============================================================
# LOOKALIKE DOMAIN EVIDENCE
# ============================================================

def analyze_lookalike_evidence(
    lookalike_analysis: dict
) -> dict:

    detected = bool(
        lookalike_analysis.get(
            "is_lookalike",
            False
        )
    )

    risk = str(
        lookalike_analysis.get(
            "risk",
            "LOW"
        )
    ).upper()

    similarity = (
        lookalike_analysis.get(
            "similarity",
            0
        )
    )

    matched_brand = (
        lookalike_analysis.get(
            "matched_brand"
        )
    )

    matched_domain = (
        lookalike_analysis.get(
            "matched_domain"
        )
    )

    if not detected:

        score = 0

    elif risk == "HIGH":

        score = 100

    elif risk == "MEDIUM":

        score = 60

    else:

        score = 30

    return {

        "detected": detected,

        "score": score,

        "risk": risk,

        "similarity": similarity,

        "matched_brand": matched_brand,

        "matched_domain": matched_domain
    }


# ============================================================
# AUTHENTICATION EVIDENCE
# ============================================================

def analyze_authentication_evidence(
    authentication_analysis: dict
) -> dict:

    failures = []

    checks = [
        "spf",
        "dkim",
        "dmarc"
    ]

    for check in checks:

        result = (
            authentication_analysis.get(
                check,
                {}
            )
        )

        if not isinstance(
            result,
            dict
        ):
            continue

        status = str(
            result.get(
                "status",
                ""
            )
        ).lower()

        authentication_result = str(
            result.get(
                "result",
                ""
            )
        ).lower()

        if (
            status == "suspicious"
            or authentication_result == "fail"
        ):

            failures.append(
                check.upper()
            )

    # Authentication is one evidence source.
    #
    # One failure is meaningful.
    # Multiple independent failures are stronger.
    #
    # Normalize to 0-100.

    score = min(
        len(failures) * 35,
        100
    )

    return {

        "score": score,

        "failures": failures,

        "failure_count": len(
            failures
        ),

        "all_failed": (
            len(failures) == 3
        )
    }


# ============================================================
# URL EVIDENCE
# ============================================================

def analyze_url_evidence(
    url_intelligence: list
) -> dict:

    if not isinstance(
        url_intelligence,
        list
    ):
        url_intelligence = []

    suspicious_urls = []

    scores = []

    for item in url_intelligence:

        if not isinstance(
            item,
            dict
        ):
            continue

        risk = str(
            item.get(
                "risk",
                "LOW"
            )
        ).upper()

        risk_score = safe_int(
            item.get(
                "risk_score",
                0
            )
        )

        risk_score = clamp(
            risk_score
        )

        scores.append(
            risk_score
        )

        if risk in [
            "HIGH",
            "CRITICAL"
        ]:

            suspicious_urls.append(
                item
            )

    if scores:

        average_score = (
            sum(scores)
            / len(scores)
        )

    else:

        average_score = 0

    return {

        "score": clamp(
            average_score
        ),

        "url_count": len(
            url_intelligence
        ),

        "suspicious_url_count": len(
            suspicious_urls
        ),

        "suspicious_urls": (
            suspicious_urls
        )
    }


# ============================================================
# ATTACHMENT EVIDENCE
# ============================================================

def analyze_attachment_evidence(
    attachments: list
) -> dict:

    if not isinstance(
        attachments,
        list
    ):
        attachments = []

    executable_extensions = {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".msi",
        ".js",
        ".vbs",
        ".ps1"
    }

    executable_count = 0
    hashed_count = 0

    attachment_evidence = []

    for attachment in attachments:

        if not isinstance(
            attachment,
            dict
        ):
            continue

        filename = str(
            attachment.get(
                "filename",
                ""
            )
        )

        filename_lower = (
            filename.lower()
        )

        sha256 = attachment.get(
            "sha256"
        )

        if sha256:

            hashed_count += 1

        is_executable = any(
            filename_lower.endswith(
                extension
            )
            for extension
            in executable_extensions
        )

        if is_executable:

            executable_count += 1

            attachment_evidence.append({

                "filename": filename,

                "sha256": sha256,

                "type": "EXECUTABLE"
            })

    score = 0

    if attachments:

        score += 30

    if executable_count:

        score += 70

    return {

        "score": min(
            score,
            100
        ),

        "attachment_count": len(
            attachments
        ),

        "executable_count": (
            executable_count
        ),

        "hashed_count": hashed_count,

        "evidence": (
            attachment_evidence
        )
    }


# ============================================================
# GRAPH CORRELATION EVIDENCE
# ============================================================

def analyze_graph_evidence(
    correlation: dict
) -> dict:

    if not isinstance(
        correlation,
        dict
    ):
        correlation = {}

    score = safe_int(
        correlation.get(
            "correlation_score",
            0
        )
    )

    classification = str(
        correlation.get(
            "classification",
            "NO STRONG CORRELATION"
        )
    )

    related_case_count = safe_int(
        correlation.get(
            "related_case_count",
            0
        )
    )

    shared_indicators = (
        correlation.get(
            "shared_indicators",
            {}
        )
    )

    if not isinstance(
        shared_indicators,
        dict
    ):
        shared_indicators = {}

    indicator_types = [
        key
        for key, values
        in shared_indicators.items()
        if values
    ]

    # --------------------------------------------------------
    # Strengthen graph evidence when multiple independent
    # infrastructure types are shared.
    # --------------------------------------------------------

    if related_case_count >= 5:

        score = max(
            score,
            100
        )

    elif related_case_count >= 2:

        score = max(
            score,
            70
        )

    # Four independent IOC types are especially strong
    # campaign evidence.

    if len(
        indicator_types
    ) >= 4:

        score = max(
            score,
            100
        )

    return {

        "score": clamp(
            score
        ),

        "classification": (
            classification
        ),

        "related_case_count": (
            related_case_count
        ),

        "indicator_types": (
            indicator_types
        ),

        "shared_indicator_type_count": (
            len(indicator_types)
        ),

        "shared_indicators": (
            shared_indicators
        )
    }


# ============================================================
# ML EVIDENCE
# ============================================================

def analyze_ml_evidence(
    ml_evidence: dict
) -> dict:
    """
    Normalize ML evidence for the fusion engine.

    ML is supporting evidence, not an independent evidence
    family, because its features are derived from the other
    evidence sources.
    """

    if not isinstance(
        ml_evidence,
        dict
    ):

        return {

            "available": False,

            "classification": "UNAVAILABLE",

            "confidence": 0,

            "confidence_level": "UNAVAILABLE",

            "support_score": 0,

            "probabilities": {
                "benign": 0,
                "phishing": 0
            },

            "feature_count": 0,

            "top_model_features": [],

            "error": "Invalid ML evidence"
        }

    return {

        "available": bool(
            ml_evidence.get(
                "available",
                False
            )
        ),

        "classification": str(
            ml_evidence.get(
                "classification",
                "UNAVAILABLE"
            )
        ).upper(),

        "confidence": clamp(
            float(
                ml_evidence.get(
                    "confidence",
                    0
                )
            )
        ),

        "confidence_level": str(
            ml_evidence.get(
                "confidence_level",
                "UNAVAILABLE"
            )
        ).upper(),

        "support_score": clamp(
            float(
                ml_evidence.get(
                    "support_score",
                    0
                )
            )
        ),

        "probabilities": (
            ml_evidence.get(
                "probabilities",
                {
                    "benign": 0,
                    "phishing": 0
                }
            )
        ),

        "feature_count": safe_int(
            ml_evidence.get(
                "feature_count",
                0
            )
        ),

        "top_model_features": (
            ml_evidence.get(
                "top_model_features",
                []
            )
        ),

        "error": ml_evidence.get(
            "error"
        )
    }


# ============================================================
# FINAL CLASSIFICATION
# ============================================================

def classify_final_assessment(
    score: float,
    critical_signals: int
) -> tuple[str, str]:

    # --------------------------------------------------------
    # Very strong multi-source evidence
    # --------------------------------------------------------

    if (
        score >= 75
        and critical_signals >= 4
    ):

        return (
            "CRITICAL",
            "HIGH CONFIDENCE THREAT"
        )

    # --------------------------------------------------------
    # Strong evidence
    # --------------------------------------------------------

    if (
        score >= 60
        and critical_signals >= 3
    ):

        return (
            "HIGH",
            "LIKELY THREAT"
        )

    # --------------------------------------------------------
    # Suspicious
    # --------------------------------------------------------

    if score >= 35:

        return (
            "MEDIUM",
            "SUSPICIOUS"
        )

    # --------------------------------------------------------
    # Low
    # --------------------------------------------------------

    return (
        "LOW",
        "NO STRONG THREAT SIGNAL"
    )


# ============================================================
# BUILD EXPLANATION
# ============================================================

def build_final_explanation(
    forensic: dict,
    nlp: dict,
    lookalike: dict,
    authentication: dict,
    urls: dict,
    attachments: dict,
    graph: dict,
    ml: dict
) -> list[str]:

    explanations = []

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    if authentication[
        "failure_count"
    ]:

        explanations.append(
            "Email authentication failures "
            "were detected: "
            + ", ".join(
                authentication[
                    "failures"
                ]
            )
        )

    # --------------------------------------------------------
    # NLP
    # --------------------------------------------------------

    if nlp[
        "detected_categories"
    ]:

        explanations.append(
            "Threat-language signals detected: "
            + ", ".join(
                nlp[
                    "detected_categories"
                ]
            )
        )

    # --------------------------------------------------------
    # Lookalike
    # --------------------------------------------------------

    if lookalike[
        "detected"
    ]:

        brand = (
            lookalike[
                "matched_brand"
            ]
            or "known brand"
        )

        explanations.append(
            "Lookalike-domain evidence "
            f"suggests impersonation of {brand}"
        )

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    if urls[
        "suspicious_url_count"
    ]:

        explanations.append(
            f"{urls['suspicious_url_count']} "
            "high-risk URL(s) detected"
        )

    # --------------------------------------------------------
    # Attachment
    # --------------------------------------------------------

    if attachments[
        "executable_count"
    ]:

        explanations.append(
            f"{attachments['executable_count']} "
            "executable attachment(s) detected"
        )

    # --------------------------------------------------------
    # Graph
    # --------------------------------------------------------

    if graph[
        "related_case_count"
    ]:

        explanations.append(
            f"{graph['related_case_count']} "
            "related case(s) found through "
            "graph correlation"
        )

    if graph[
        "indicator_types"
    ]:

        explanations.append(
            "Shared infrastructure includes: "
            + ", ".join(
                graph[
                    "indicator_types"
                ]
            )
        )

    # --------------------------------------------------------
    # Forensic evidence
    # --------------------------------------------------------

    if forensic[
        "evidence_count"
    ]:

        explanations.append(
            f"{forensic['evidence_count']} "
            "forensic evidence signal(s) "
            "contributed to the assessment"
        )

    # --------------------------------------------------------
    # Machine Learning
    # --------------------------------------------------------

    if ml[
        "available"
    ]:

        classification = ml[
            "classification"
        ]

        confidence = ml[
            "confidence"
        ]

        if classification == "PHISHING":

            explanations.append(
                "Machine-learning analysis "
                f"classified the email as PHISHING "
                f"with {confidence:.1f}% confidence"
            )

        elif classification == "BENIGN":

            explanations.append(
                "Machine-learning analysis "
                f"classified the email as BENIGN "
                f"with {confidence:.1f}% confidence"
            )

    return explanations


# ============================================================
# MAIN EVIDENCE FUSION
# ============================================================

def fuse_evidence(
    risk_assessment: dict,
    nlp_analysis: dict,
    lookalike_analysis: dict,
    authentication_analysis: dict,
    url_intelligence: list,
    attachments: list,
    correlation: dict
) -> dict:

    # ========================================================
    # INDIVIDUAL SOURCES
    # ========================================================

    forensic = (
        analyze_forensic_evidence(
            risk_assessment
        )
    )

    nlp = (
        analyze_nlp_evidence(
            nlp_analysis
        )
    )

    lookalike = (
        analyze_lookalike_evidence(
            lookalike_analysis
        )
    )

    authentication = (
        analyze_authentication_evidence(
            authentication_analysis
        )
    )

    urls = (
        analyze_url_evidence(
            url_intelligence
        )
    )

    attachments_result = (
        analyze_attachment_evidence(
            attachments
        )
    )

    graph = (
        analyze_graph_evidence(
            correlation
        )
    )

    # ========================================================
    # MACHINE LEARNING
    # ========================================================
    #
    # Build the same evidence structure consumed by the ML
    # feature extractor.
    #
    # ML therefore sees the exact evidence generated by the
    # TRACE-AI pipeline rather than a separate duplicate
    # analysis.
    # ========================================================

    combined_evidence = {

        "risk_assessment": risk_assessment,

        "nlp_analysis": nlp_analysis,

        "lookalike_analysis": lookalike_analysis,

        "authentication_analysis": (
            authentication_analysis
        ),

        "url_intelligence": (
            url_intelligence
        ),

        "attachments": attachments,

        "correlation": {

            "result": correlation
        }
    }

    ml_raw = build_ml_evidence(
        combined_evidence
    )

    ml = analyze_ml_evidence(
        ml_raw
    )

    # ========================================================
    # BASE WEIGHTED SCORE
    # ========================================================
    #
    # Existing deterministic evidence receives 90% of the
    # score.
    #
    # ML receives up to 10% as supporting evidence.
    #
    # This prevents the experimental seed-trained model from
    # dominating the forensic evidence.
    #
    # These weights are engineering choices and should
    # eventually be calibrated on a real labelled dataset.
    # ========================================================

    base_score = (

        forensic["score"] * 0.225

        + nlp["score"] * 0.180

        + lookalike["score"] * 0.135

        + authentication["score"] * 0.135

        + urls["score"] * 0.045

        + attachments_result["score"] * 0.090

        + graph["score"] * 0.090

        + ml["support_score"] * 0.100
    )

    # ========================================================
    # INDEPENDENT EVIDENCE BONUS
    # ========================================================
    #
    # IMPORTANT:
    # ML is deliberately NOT counted here because its
    # features are derived from these evidence sources.
    #
    # This prevents double-counting.
    # ========================================================

    evidence_families = 0

    if forensic["score"] >= 70:

        evidence_families += 1

    if nlp["score"] >= 60:

        evidence_families += 1

    if lookalike["detected"]:

        evidence_families += 1

    if authentication[
        "failure_count"
    ] >= 2:

        evidence_families += 1

    if (
        attachments_result[
            "executable_count"
        ] > 0
    ):

        evidence_families += 1

    if graph[
        "related_case_count"
    ] >= 2:

        evidence_families += 1

    # --------------------------------------------------------
    # Multi-source reinforcement
    # --------------------------------------------------------

    if evidence_families >= 6:

        base_score += 25

    elif evidence_families >= 5:

        base_score += 20

    elif evidence_families >= 4:

        base_score += 12

    elif evidence_families >= 3:

        base_score += 6

    # ========================================================
    # ML REINFORCEMENT
    # ========================================================
    #
    # A strong phishing prediction adds a small additional
    # reinforcement.
    #
    # This is separate from evidence_families because ML is
    # not independent evidence.
    # ========================================================

    ml_reinforcement = 0

    if (
        ml["available"]
        and ml["classification"] == "PHISHING"
        and ml["confidence"] >= 75
    ):

        ml_reinforcement = 3

        base_score += ml_reinforcement

    # ========================================================
    # CRITICAL SIGNAL COUNT
    # ========================================================

    critical_signals = 0

    if forensic[
        "score"
    ] >= 70:

        critical_signals += 1

    if nlp[
        "score"
    ] >= 70:

        critical_signals += 1

    if (
        lookalike[
            "detected"
        ]
        and lookalike[
            "risk"
        ] == "HIGH"
    ):

        critical_signals += 1

    if (
        authentication[
            "failure_count"
        ] >= 2
    ):

        critical_signals += 1

    if (
        attachments_result[
            "executable_count"
        ] > 0
    ):

        critical_signals += 1

    if (
        graph[
            "related_case_count"
        ] >= 2
    ):

        critical_signals += 1

    # ========================================================
    # FINAL SCORE
    # ========================================================

    final_score = round(
        clamp(
            base_score
        ),
        2
    )

    # ========================================================
    # FINAL CLASSIFICATION
    # ========================================================

    threat_level, classification = (
        classify_final_assessment(
            final_score,
            critical_signals
        )
    )

    # ========================================================
    # EXPLANATION
    # ========================================================

    explanation = (
        build_final_explanation(
            forensic=forensic,
            nlp=nlp,
            lookalike=lookalike,
            authentication=authentication,
            urls=urls,
            attachments=attachments_result,
            graph=graph,
            ml=ml
        )
    )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "engine": (
            "TRACE-AI Evidence Fusion Engine"
        ),

        "assessment_type": (
            "Multi-source explainable "
            "threat assessment"
        ),

        "final_score": final_score,

        "threat_level": threat_level,

        "classification": classification,

        "critical_signal_count": (
            critical_signals
        ),

        "evidence_family_count": (
            evidence_families
        ),

        "ml_reinforcement": (
            ml_reinforcement
        ),

        "confidence_note": (
            "Engineering assessment score; "
            "not a calibrated probability."
        ),

        "evidence_sources": {

            "forensic": forensic,

            "nlp": nlp,

            "lookalike": lookalike,

            "authentication": authentication,

            "urls": urls,

            "attachments": attachments_result,

            "graph": graph,

            "machine_learning": ml
        },

        "explanation": explanation
    }