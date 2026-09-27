from typing import Any

from app.ml.dataset import FEATURE_NAMES, build_feature_vector


# ============================================================
# TRACE-AI ML FEATURE EXTRACTION
# ============================================================
# Converts the complete TRACE-AI evidence result into a
# standardized ML feature representation.
#
# The actual feature definitions are maintained in dataset.py.
# This file acts as the production-facing adapter for the ML
# pipeline.
# ============================================================


def extract_ml_features(evidence: dict) -> dict[str, Any]:
    """
    Extract the standardized ML feature vector from a
    TRACE-AI evidence dictionary.

    Returns:
        {
            "feature_names": [...],
            "features": [...],
            "feature_map": {
                "spf_fail": 0,
                ...
            }
        }
    """

    if not isinstance(evidence, dict):
        raise TypeError("evidence must be a dictionary")

    vector = build_feature_vector(
        risk_assessment=evidence.get("risk_assessment", {}),
        nlp_analysis=evidence.get("nlp_analysis", {}),
        lookalike_analysis=evidence.get("lookalike_analysis", {}),
        authentication_analysis=evidence.get(
            "authentication_analysis", {}
        ),
        url_intelligence=evidence.get(
            "url_intelligence", []
        ),
        attachments=evidence.get(
            "attachments", []
        ),
        correlation=(
            evidence.get("correlation", {})
            .get("result", {})
            or {}
        ),
    )

    feature_map = dict(zip(FEATURE_NAMES, vector))

    return {
        "feature_names": FEATURE_NAMES,
        "features": vector,
        "feature_map": feature_map,
    }


def validate_feature_vector(
    vector: list[float],
) -> bool:
    """
    Validate that an ML feature vector has the
    expected number of numeric features.
    """

    if not isinstance(vector, list):
        return False

    if len(vector) != len(FEATURE_NAMES):
        return False

    for value in vector:
        if not isinstance(value, (int, float)):
            return False

    return True


def feature_map_from_vector(
    vector: list[float],
) -> dict[str, float]:
    """
    Convert a feature vector back into a named dictionary.
    """

    if not validate_feature_vector(vector):
        raise ValueError(
            f"Invalid feature vector. Expected "
            f"{len(FEATURE_NAMES)} numeric values."
        )

    return dict(zip(FEATURE_NAMES, vector))


def print_feature_report(
    feature_data: dict[str, Any],
) -> None:
    """
    Print a human-readable feature report for debugging.
    """

    print("\nTRACE-AI ML FEATURE REPORT")
    print("==========================")

    feature_map = feature_data.get(
        "feature_map", {}
    )

    for index, name in enumerate(FEATURE_NAMES):
        value = feature_map.get(name, 0)

        print(
            f"{index:02d}. "
            f"{name:<28} = {value}"
        )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    # Small synthetic evidence object used only to verify
    # that the feature extraction pipeline works.

    test_evidence = {
        "risk_assessment": {
            "risk_score": 75
        },

        "authentication_analysis": {
            "spf": {
                "result": "fail"
            },
            "dkim": {
                "result": "fail"
            },
            "dmarc": {
                "result": "fail"
            }
        },

        "url_intelligence": [
            {
                "url": "https://example.com/login",
                "risk": "HIGH"
            }
        ],

        "lookalike_analysis": {
            "is_lookalike": True,
            "similarity": 92
        },

        "attachments": [
            {
                "filename": "invoice.exe"
            }
        ],

        "nlp_analysis": {
            "nlp_score": 75,
            "categories": {
                "urgency": {
                    "detected": True
                },
                "credential_request": {
                    "detected": True
                },
                "fear_or_threat": {
                    "detected": True
                },
                "financial_pressure": {
                    "detected": False
                },
                "authority_or_impersonation": {
                    "detected": True
                },
                "secrecy": {
                    "detected": False
                },
                "call_to_action": {
                    "detected": True
                },
                "download_or_installation": {
                    "detected": True
                }
            }
        },

        "correlation": {
            "result": {
                "related_case_count": 4,
                "correlation_score": 90
            }
        }
    }

    result = extract_ml_features(test_evidence)

    print_feature_report(result)

    print("\nValidation:")
    print(validate_feature_vector(result["features"]))

    print("\nFeature count:")
    print(len(result["features"]))