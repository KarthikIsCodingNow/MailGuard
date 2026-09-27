from __future__ import annotations
from typing import Any


# ============================================================
# TRACE-AI ML DATASET BUILDER
# ============================================================
#
# Creates labelled training samples from TRACE-AI evidence.
#
# Label:
#   1 = PHISHING / MALICIOUS
#   0 = BENIGN
#
# This is the first reproducible dataset layer.
# Later we can replace/extend the seed data with a real
# labelled email dataset.
# ============================================================


# ============================================================
# FEATURE NAMES
# ============================================================

FEATURE_NAMES = [

    # Authentication
    "spf_fail",
    "dkim_fail",
    "dmarc_fail",

    # Email / URL
    "url_count",
    "suspicious_url_count",

    # Domain
    "lookalike_detected",
    "lookalike_similarity",

    # Attachments
    "attachment_count",
    "executable_attachment",

    # NLP
    "nlp_score",
    "urgency",
    "credential_request",
    "fear_or_threat",
    "financial_pressure",
    "authority_impersonation",
    "secrecy",
    "call_to_action",
    "download_installation",

    # Graph
    "related_case_count",
    "correlation_score",
]


# ============================================================
# SAFE HELPERS
# ============================================================

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


def safe_float(
    value: Any,
    default: float = 0.0
) -> float:

    try:
        return float(value)

    except (
        TypeError,
        ValueError
    ):

        return default


def detected(
    categories: dict,
    name: str
) -> int:

    item = categories.get(
        name,
        {}
    )

    if not isinstance(
        item,
        dict
    ):

        return 0

    return int(
        bool(
            item.get(
                "detected",
                False
            )
        )
    )


# ============================================================
# BUILD ONE FEATURE VECTOR
# ============================================================

def build_feature_vector(
    risk_assessment: dict | None = None,
    nlp_analysis: dict | None = None,
    lookalike_analysis: dict | None = None,
    authentication_analysis: dict | None = None,
    url_intelligence: list | None = None,
    attachments: list | None = None,
    correlation: dict | None = None,
) -> list[float]:

    risk_assessment = (
        risk_assessment
        or {}
    )

    nlp_analysis = (
        nlp_analysis
        or {}
    )

    lookalike_analysis = (
        lookalike_analysis
        or {}
    )

    authentication_analysis = (
        authentication_analysis
        or {}
    )

    url_intelligence = (
        url_intelligence
        or []
    )

    attachments = (
        attachments
        or []
    )

    correlation = (
        correlation
        or {}
    )

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    spf = authentication_analysis.get(
        "spf",
        {}
    )

    dkim = authentication_analysis.get(
        "dkim",
        {}
    )

    dmarc = authentication_analysis.get(
        "dmarc",
        {}
    )

    spf_fail = int(
        str(
            spf.get(
                "result",
                ""
            )
        ).lower()
        == "fail"
    )

    dkim_fail = int(
        str(
            dkim.get(
                "result",
                ""
            )
        ).lower()
        == "fail"
    )

    dmarc_fail = int(
        str(
            dmarc.get(
                "result",
                ""
            )
        ).lower()
        == "fail"
    )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    url_count = len(
        url_intelligence
    )

    suspicious_url_count = 0

    for item in url_intelligence:

        if not isinstance(
            item,
            dict
        ):
            continue

        risk = str(
            item.get(
                "risk",
                ""
            )
        ).upper()

        if risk in {
            "HIGH",
            "CRITICAL"
        }:

            suspicious_url_count += 1

    # --------------------------------------------------------
    # Lookalike
    # --------------------------------------------------------

    lookalike_detected = int(
        bool(
            lookalike_analysis.get(
                "is_lookalike",
                False
            )
        )
    )

    lookalike_similarity = safe_float(
        lookalike_analysis.get(
            "similarity",
            0
        )
    )

    # --------------------------------------------------------
    # Attachments
    # --------------------------------------------------------

    attachment_count = len(
        attachments
    )

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

    executable_attachment = 0

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
        ).lower()

        if any(
            filename.endswith(
                extension
            )
            for extension
            in executable_extensions
        ):

            executable_attachment = 1

            break

    # --------------------------------------------------------
    # NLP
    # --------------------------------------------------------

    nlp_score = safe_int(
        nlp_analysis.get(
            "nlp_score",
            0
        )
    )

    categories = nlp_analysis.get(
        "categories",
        {}
    )

    if not isinstance(
        categories,
        dict
    ):

        categories = {}

    urgency = detected(
        categories,
        "urgency"
    )

    credential_request = detected(
        categories,
        "credential_request"
    )

    fear_or_threat = detected(
        categories,
        "fear_or_threat"
    )

    financial_pressure = detected(
        categories,
        "financial_pressure"
    )

    authority_impersonation = detected(
        categories,
        "authority_or_impersonation"
    )

    secrecy = detected(
        categories,
        "secrecy"
    )

    call_to_action = detected(
        categories,
        "call_to_action"
    )

    download_installation = detected(
        categories,
        "download_or_installation"
    )

    # --------------------------------------------------------
    # Graph correlation
    # --------------------------------------------------------

    related_case_count = safe_int(
        correlation.get(
            "related_case_count",
            0
        )
    )

    correlation_score = safe_float(
        correlation.get(
            "correlation_score",
            0
        )
    )

    # --------------------------------------------------------
    # Final vector
    # --------------------------------------------------------

    vector = [

        spf_fail,

        dkim_fail,

        dmarc_fail,

        url_count,

        suspicious_url_count,

        lookalike_detected,

        lookalike_similarity,

        attachment_count,

        executable_attachment,

        nlp_score,

        urgency,

        credential_request,

        fear_or_threat,

        financial_pressure,

        authority_impersonation,

        secrecy,

        call_to_action,

        download_installation,

        related_case_count,

        correlation_score,
    ]

    return vector


# ============================================================
# CONVERT TRACE-AI RESULT TO ML SAMPLE
# ============================================================

def evidence_to_sample(
    evidence: dict,
    label: int
) -> dict:

    vector = build_feature_vector(

        risk_assessment=evidence.get(
            "risk_assessment",
            {}
        ),

        nlp_analysis=evidence.get(
            "nlp_analysis",
            {}
        ),

        lookalike_analysis=evidence.get(
            "lookalike_analysis",
            {}
        ),

        authentication_analysis=evidence.get(
            "authentication_analysis",
            {}
        ),

        url_intelligence=evidence.get(
            "url_intelligence",
            []
        ),

        attachments=evidence.get(
            "attachments",
            []
        ),

        correlation=(
            evidence
            .get(
                "correlation",
                {}
            )
            .get(
                "result",
                {}
            )
            or {}
        ),
    )

    return {

        "features": vector,

        "label": int(
            label
        )
    }


# ============================================================
# FEATURE MATRIX
# ============================================================

def build_feature_matrix(
    samples: list[dict]
) -> tuple[list[list[float]], list[int]]:

    X = []
    y = []

    for sample in samples:

        if not isinstance(
            sample,
            dict
        ):

            continue

        features = sample.get(
            "features"
        )

        label = sample.get(
            "label"
        )

        if not isinstance(
            features,
            list
        ):

            continue

        if label not in {
            0,
            1
        }:

            continue

        X.append(
            features
        )

        y.append(
            int(label)
        )

    return X, y


# ============================================================
# SEED DATASET
# ============================================================
#
# These are synthetic examples used ONLY to verify the ML
# pipeline before introducing a real labelled dataset.
#
# They should NOT be presented as a real-world benchmark.
# ============================================================

def create_seed_dataset() -> tuple[
    list[list[float]],
    list[int]
]:

    # --------------------------------------------------------
    # BENIGN SAMPLE 1
    # --------------------------------------------------------

    benign_1 = [
        0,      # spf_fail
        0,      # dkim_fail
        0,      # dmarc_fail
        1,      # url_count
        0,      # suspicious_url_count
        0,      # lookalike_detected
        0.0,    # similarity
        0,      # attachments
        0,      # executable
        5,      # nlp
        0,      # urgency
        0,      # credential
        0,      # fear
        0,      # financial
        0,      # authority
        0,      # secrecy
        0,      # CTA
        0,      # download
        0,      # related cases
        0,      # correlation
    ]

    # --------------------------------------------------------
    # BENIGN SAMPLE 2
    # --------------------------------------------------------

    benign_2 = [
        0,
        0,
        0,
        2,
        0,
        0,
        0.0,
        1,
        0,
        10,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]

    # --------------------------------------------------------
    # BENIGN SAMPLE 3
    # --------------------------------------------------------

    benign_3 = [
        0,
        0,
        0,
        0,
        0,
        0,
        0.0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]

    # --------------------------------------------------------
    # PHISHING SAMPLE 1
    # --------------------------------------------------------

    phishing_1 = [
        1,
        1,
        1,
        2,
        1,
        1,
        100.0,
        1,
        1,
        75,
        1,
        1,
        1,
        0,
        1,
        0,
        1,
        0,
        5,
        100,
    ]

    # --------------------------------------------------------
    # PHISHING SAMPLE 2
    # --------------------------------------------------------

    phishing_2 = [
        1,
        1,
        1,
        1,
        1,
        1,
        90.0,
        0,
        0,
        70,
        1,
        1,
        1,
        0,
        1,
        0,
        1,
        0,
        3,
        75,
    ]

    # --------------------------------------------------------
    # PHISHING SAMPLE 3
    # --------------------------------------------------------

    phishing_3 = [
        1,
        0,
        1,
        3,
        2,
        1,
        85.0,
        1,
        1,
        80,
        1,
        1,
        1,
        1,
        1,
        0,
        1,
        0,
        4,
        90,
    ]

    X = [
        benign_1,
        benign_2,
        benign_3,
        phishing_1,
        phishing_2,
        phishing_3,
    ]

    y = [
        0,
        0,
        0,
        1,
        1,
        1,
    ]

    return X, y


# ============================================================
# DATASET SUMMARY
# ============================================================

def dataset_summary(
    X: list[list[float]],
    y: list[int]
) -> dict[str, Any]:

    benign_count = sum(
        1
        for label in y
        if label == 0
    )

    phishing_count = sum(
        1
        for label in y
        if label == 1
    )

    return {

        "samples": len(X),

        "features": len(
            FEATURE_NAMES
        ),

        "feature_names": (
            FEATURE_NAMES
        ),

        "benign_samples": (
            benign_count
        ),

        "phishing_samples": (
            phishing_count
        ),

        "note": (
            "Seed dataset is synthetic and "
            "is intended only for pipeline "
            "development/testing."
        )
    }


# ============================================================
# SCRIPT ENTRY POINT
# ============================================================

if __name__ == "__main__":

    X, y = create_seed_dataset()

    summary = dataset_summary(
        X,
        y
    )

    print(
        "\nTRACE-AI ML DATASET"
    )

    print(
        "==================="
    )

    print(
        f"Samples: {summary['samples']}"
    )

    print(
        f"Features: {summary['features']}"
    )

    print(
        f"Benign: {summary['benign_samples']}"
    )

    print(
        f"Phishing: {summary['phishing_samples']}"
    )

    print(
        "\nFeature names:"
    )

    for index, name in enumerate(
        FEATURE_NAMES
    ):

        print(
            f"{index:02d}. {name}"
        )