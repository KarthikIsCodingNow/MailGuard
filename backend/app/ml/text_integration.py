from __future__ import annotations
from typing import Any

from app.ml.predict_text import TRACEAITextClassifier


# ============================================================
# TRACE-AI TEXT ML INTEGRATION
# ============================================================
#
# Connects the real SpamAssassin-trained text classifier to
# the TRACE-AI evidence pipeline.
#
# Classification:
#   HAM  = text resembles legitimate/benign email
#   SPAM = text resembles spam
#
# IMPORTANT:
# SPAM is not automatically PHISHING.
#
# This module therefore reports the text classification as
# separate evidence instead of directly converting SPAM into
# a phishing verdict.
# ============================================================


_text_classifier: TRACEAITextClassifier | None = None


# ============================================================
# CLASSIFIER LOADER
# ============================================================

def get_text_classifier() -> TRACEAITextClassifier:
    """
    Load the text classifier once and reuse it.
    """

    global _text_classifier

    if _text_classifier is None:

        _text_classifier = (
            TRACEAITextClassifier()
        )

    return _text_classifier


# ============================================================
# RUN TEXT ANALYSIS
# ============================================================

def run_text_ml_analysis(
    email_text: str,
) -> dict[str, Any]:
    """
    Run the real email text classifier.
    """

    if not isinstance(
        email_text,
        str
    ):

        return {

            "available": False,

            "classification": "UNAVAILABLE",

            "confidence": 0,

            "confidence_level": "UNAVAILABLE",

            "probabilities": {
                "ham": 0,
                "spam": 0
            },

            "model": (
                "TRACE-AI TF-IDF + "
                "Logistic Regression"
            ),

            "error": (
                "email_text must be a string"
            )
        }

    if not email_text.strip():

        return {

            "available": False,

            "classification": "UNAVAILABLE",

            "confidence": 0,

            "confidence_level": "UNAVAILABLE",

            "probabilities": {
                "ham": 0,
                "spam": 0
            },

            "model": (
                "TRACE-AI TF-IDF + "
                "Logistic Regression"
            ),

            "error": (
                "Email text is empty"
            )
        }

    try:

        classifier = (
            get_text_classifier()
        )

        result = classifier.predict(
            email_text
        )

        return {

            "available": True,

            "model": result.get(
                "model",
                "TRACE-AI TF-IDF + "
                "Logistic Regression"
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
                    "ham": 0,
                    "spam": 0
                }
            ),

            "error": None
        }

    except Exception as error:

        return {

            "available": False,

            "model": (
                "TRACE-AI TF-IDF + "
                "Logistic Regression"
            ),

            "classification": "UNAVAILABLE",

            "confidence": 0,

            "confidence_level": "UNAVAILABLE",

            "probabilities": {
                "ham": 0,
                "spam": 0
            },

            "error": repr(error)
        }


# ============================================================
# COMPATIBILITY ALIASES
# ============================================================

predict_text = run_text_ml_analysis
predict_email = run_text_ml_analysis
predict_email_text = run_text_ml_analysis
classify_text = run_text_ml_analysis
run_prediction = run_text_ml_analysis


# ============================================================
# TEXT SUPPORT SCORE
# ============================================================

def text_support_score(
    text_result: dict,
) -> float:
    """
    Convert the text classifier result into a supporting
    evidence score from 0 to 100.

    This is an engineering support score.
    It is NOT a probability of phishing.
    """

    if not isinstance(
        text_result,
        dict
    ):

        return 0.0

    if not text_result.get(
        "available",
        False
    ):

        return 0.0

    classification = str(
        text_result.get(
            "classification",
            ""
        )
    ).upper()

    confidence = float(
        text_result.get(
            "confidence",
            0
        )
    )

    # A SPAM classification provides some suspicious-text
    # support.

    if classification == "SPAM":

        return round(
            confidence,
            2
        )

    # HAM provides no positive threat support.

    if classification == "HAM":

        return 0.0

    return 0.0


# ============================================================
# BUILD TEXT EVIDENCE
# ============================================================

def build_text_ml_evidence(
    email_text: str,
) -> dict[str, Any]:
    """
    Build the normalized text ML evidence block.
    """

    result = run_text_ml_analysis(
        email_text
    )

    support_score = (
        text_support_score(
            result
        )
    )

    return {

        "source": "text_machine_learning",

        "available": result[
            "available"
        ],

        "model": result[
            "model"
        ],

        "classification": result[
            "classification"
        ],

        "confidence": result[
            "confidence"
        ],

        "confidence_level": result[
            "confidence_level"
        ],

        "probabilities": result[
            "probabilities"
        ],

        "support_score": support_score,

        "error": result[
            "error"
        ]
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print(
        "\nTRACE-AI TEXT ML INTEGRATION TEST"
    )

    print(
        "================================="
    )

    test_email = """
    Subject: Urgent account verification required

    Your account requires immediate verification.

    Please click the link below to confirm your
    account information and avoid suspension.

    Thank you.
    """

    result = build_text_ml_evidence(
        test_email
    )

    print(
        "\nAVAILABLE:"
    )

    print(
        result["available"]
    )

    print(
        "\nMODEL:"
    )

    print(
        result["model"]
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
            "\nTEXT ML INTEGRATION SUCCESSFUL"
        )