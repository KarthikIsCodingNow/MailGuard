from __future__ import annotations
from typing import Any

from app.ml.predict import TRACEAIClassifier


# ============================================================
# TRACE-AI ML EVIDENCE INTEGRATION
# ============================================================
#
# This module connects the trained ML classifier to the
# existing TRACE-AI evidence pipeline.
#
# It does NOT replace:
#   - Email forensics
#   - SPF/DKIM/DMARC
#   - URL intelligence
#   - Domain intelligence
#   - Lookalike detection
#   - Attachment analysis
#   - NLP analysis
#   - Neo4j correlation
#   - Deterministic evidence fusion
#
# ML is treated as an additional evidence family.
# ============================================================


_classifier: TRACEAIClassifier | None = None


def get_classifier() -> TRACEAIClassifier:
    """
    Load the ML classifier once and reuse it.

    This avoids loading model.pkl from disk for every email.
    """

    global _classifier

    if _classifier is None:
        _classifier = TRACEAIClassifier()

    return _classifier


def run_ml_analysis(
    evidence: dict,
) -> dict[str, Any]:
    """
    Run ML classification against the complete TRACE-AI
    evidence object.

    Returns a normalized ML evidence block that can be
    consumed by the Evidence Fusion Engine.
    """

    if not isinstance(evidence, dict):
        raise TypeError(
            "evidence must be a dictionary"
        )

    try:

        classifier = get_classifier()

        result = classifier.predict(
            evidence
        )

        return {
            "available": True,

            "model": result.get(
                "model",
                "TRACE-AI Random Forest"
            ),

            "prediction": result.get(
                "prediction"
            ),

            "classification": result.get(
                "classification",
                "UNKNOWN"
            ),

            "confidence": result.get(
                "confidence",
                0
            ),

            "confidence_level": result.get(
                "confidence_level",
                "LOW"
            ),

            "probabilities": result.get(
                "probabilities",
                {
                    "benign": 0,
                    "phishing": 0
                }
            ),

            "feature_count": result.get(
                "feature_count",
                0
            ),

            "features": result.get(
                "features",
                {}
            ),

            "top_model_features": result.get(
                "top_model_features",
                []
            ),

            "error": None
        }

    except Exception as error:

        # ML failure should NOT bring down the entire
        # forensic analysis pipeline.
        #
        # The deterministic evidence engines can still
        # produce a result.

        return {
            "available": False,

            "model": "TRACE-AI Random Forest",

            "prediction": None,

            "classification": "UNAVAILABLE",

            "confidence": 0,

            "confidence_level": "UNAVAILABLE",

            "probabilities": {
                "benign": 0,
                "phishing": 0
            },

            "feature_count": 0,

            "features": {},

            "top_model_features": [],

            "error": str(error)
        }


def ml_support_score(
    ml_result: dict,
) -> float:
    """
    Convert the ML result into a normalized supporting
    evidence score from 0 to 100.

    This is NOT a probability.

    It is an engineering score used by the fusion layer.
    """

    if not isinstance(
        ml_result,
        dict
    ):
        return 0.0

    if not ml_result.get(
        "available",
        False
    ):
        return 0.0

    classification = str(
        ml_result.get(
            "classification",
            ""
        )
    ).upper()

    confidence = float(
        ml_result.get(
            "confidence",
            0
        )
    )

    if classification == "PHISHING":
        return round(
            confidence,
            2
        )

    if classification == "BENIGN":
        return round(
            100.0 - confidence,
            2
        )

    return 0.0


def build_ml_evidence(
    evidence: dict,
) -> dict[str, Any]:
    """
    Produce the complete ML evidence block for the
    Evidence Fusion Engine.
    """

    ml_result = run_ml_analysis(
        evidence
    )

    support_score = ml_support_score(
        ml_result
    )

    return {
        "source": "machine_learning",

        "available": ml_result[
            "available"
        ],

        "model": ml_result[
            "model"
        ],

        "classification": ml_result[
            "classification"
        ],

        "confidence": ml_result[
            "confidence"
        ],

        "confidence_level": ml_result[
            "confidence_level"
        ],

        "probabilities": ml_result[
            "probabilities"
        ],

        "support_score": support_score,

        "feature_count": ml_result[
            "feature_count"
        ],

        "features": ml_result[
            "features"
        ],

        "top_model_features": ml_result[
            "top_model_features"
        ],

        "error": ml_result[
            "error"
        ]
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print(
        "\nTRACE-AI ML INTEGRATION TEST"
    )

    print(
        "============================"
    )

    test_evidence = {

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
                "url": "https://micros0ft.example/login",
                "risk": "HIGH"
            },

            {
                "url": "https://micros0ft.example/verify",
                "risk": "HIGH"
            }
        ],

        "lookalike_analysis": {

            "is_lookalike": True,

            "similarity": 100
        },

        "attachments": [

            {
                "filename": "security_update.exe"
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

                "related_case_count": 8,

                "correlation_score": 100
            }
        }
    }

    result = build_ml_evidence(
        test_evidence
    )

    print(
        "\nML AVAILABLE:"
    )

    print(
        result["available"]
    )

    print(
        "\nCLASSIFICATION:"
    )

    print(
        result["classification"]
    )

    print(
        "\nCONFIDENCE:"
    )

    print(
        f"{result['confidence']}%"
    )

    print(
        "\nCONFIDENCE LEVEL:"
    )

    print(
        result["confidence_level"]
    )

    print(
        "\nPROBABILITIES:"
    )

    print(
        result["probabilities"]
    )

    print(
        "\nSUPPORT SCORE:"
    )

    print(
        result["support_score"]
    )

    if result["error"]:
        print(
            "\nERROR:"
        )
        print(
            result["error"]
        )

    else:
        print(
            "\nML INTEGRATION SUCCESSFUL"
        )