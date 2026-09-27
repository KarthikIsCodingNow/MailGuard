from pathlib import Path
from typing import Any

import joblib


# ============================================================
# TRACE-AI REAL EMAIL TEXT PREDICTOR
# ============================================================
#
# Loads:
#   text_model.pkl
#
# Predicts:
#   HAM / BENIGN
#   SPAM
#
# The model was trained using:
#   TF-IDF + Logistic Regression
#
# IMPORTANT:
# SPAM is not automatically equivalent to PHISHING.
# This model is currently a spam/ham classifier.
# ============================================================


BASE_DIR = Path(__file__).resolve().parents[2]

MODEL_PATH = (
    BASE_DIR
    / "app"
    / "ml"
    / "text_model.pkl"
)


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_prediction_text(
    text: str,
) -> str:
    """
    Basic normalization before prediction.
    """

    if not isinstance(
        text,
        str
    ):
        return ""

    return text.strip()


# ============================================================
# TEXT CLASSIFIER
# ============================================================

class TRACEAITextClassifier:
    """
    Loads and uses the trained real-email text model.
    """

    def __init__(
        self,
        model_path: Path = MODEL_PATH,
    ) -> None:

        self.model_path = model_path

        self.model = None

        self.load_model()

    # --------------------------------------------------------
    # LOAD
    # --------------------------------------------------------

    def load_model(self) -> None:
        """
        Load the trained TF-IDF + Logistic Regression model.
        """

        if not self.model_path.exists():

            raise FileNotFoundError(
                f"Text model not found:\n"
                f"{self.model_path}\n\n"
                f"Run:\n"
                f"python -m app.ml.train_text"
            )

        self.model = joblib.load(
            self.model_path
        )

    # --------------------------------------------------------
    # PREDICT
    # --------------------------------------------------------

    def predict(
        self,
        text: str,
    ) -> dict[str, Any]:
        """
        Predict HAM/SPAM for a single email.
        """

        if self.model is None:

            self.load_model()

        text = clean_prediction_text(
            text
        )

        if not text:

            raise ValueError(
                "Email text cannot be empty."
            )

        # ----------------------------------------------------
        # Prediction
        # ----------------------------------------------------

        prediction = self.model.predict(
            [text]
        )[0]

        # ----------------------------------------------------
        # Probability
        # ----------------------------------------------------

        probabilities = (
            self.model.predict_proba(
                [text]
            )[0]
        )

        benign_probability = float(
            probabilities[0]
        )

        spam_probability = float(
            probabilities[1]
        )

        # ----------------------------------------------------
        # Classification
        # ----------------------------------------------------

        if int(prediction) == 1:

            classification = "SPAM"

            confidence = (
                spam_probability
            )

        else:

            classification = "HAM"

            confidence = (
                benign_probability
            )

        confidence_percentage = round(
            confidence * 100,
            2
        )

        # ----------------------------------------------------
        # Confidence level
        # ----------------------------------------------------

        if confidence >= 0.90:

            confidence_level = "VERY HIGH"

        elif confidence >= 0.75:

            confidence_level = "HIGH"

        elif confidence >= 0.60:

            confidence_level = "MEDIUM"

        else:

            confidence_level = "LOW"

        # ----------------------------------------------------
        # Result
        # ----------------------------------------------------

        return {

            "available": True,

            "model": (
                "TRACE-AI TF-IDF + "
                "Logistic Regression"
            ),

            "classification": (
                classification
            ),

            "prediction": int(
                prediction
            ),

            "confidence": (
                confidence_percentage
            ),

            "confidence_level": (
                confidence_level
            ),

            "probabilities": {

                "ham": round(
                    benign_probability * 100,
                    2
                ),

                "spam": round(
                    spam_probability * 100,
                    2
                )
            },

            "error": None
        }


# ============================================================
# CONVENIENCE FUNCTION
# ============================================================

def predict_email_text(
    text: str,
) -> dict[str, Any]:
    """
    Convenience function for single-email prediction.
    """

    classifier = (
        TRACEAITextClassifier()
    )

    return classifier.predict(
        text
    )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print(
        "\nTRACE-AI REAL TEXT ML TEST"
    )

    print(
        "=========================="
    )

    test_email = """
    Subject: Urgent account verification required

    Your account requires immediate verification.
    Please click the link below to confirm your
    account information and avoid suspension.

    Thank you.
    """

    try:

        result = predict_email_text(
            test_email
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
            "\nTEXT ML PREDICTION SUCCESSFUL"
        )

    except Exception as error:

        print(
            "\nTEXT ML PREDICTION FAILED:"
        )

        print(
            repr(error)
        )