from pathlib import Path
from typing import Any

import joblib

from app.ml.dataset import FEATURE_NAMES
from app.ml.features import extract_ml_features


# ============================================================
# TRACE-AI ML PREDICTION ENGINE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model.pkl"


class TRACEAIClassifier:
    """
    Loads the trained TRACE-AI ML model and performs
    phishing/benign classification.
    """

    def __init__(
        self,
        model_path: Path = MODEL_PATH,
    ) -> None:

        self.model_path = model_path
        self.model = None

        self.load_model()

    # --------------------------------------------------------
    # LOAD MODEL
    # --------------------------------------------------------

    def load_model(self) -> None:
        """
        Load the trained Random Forest model.
        """

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"ML model not found at:\n"
                f"{self.model_path}\n\n"
                f"Run:\n"
                f"python -m app.ml.train"
            )

        self.model = joblib.load(
            self.model_path
        )

    # --------------------------------------------------------
    # PREDICT
    # --------------------------------------------------------

    def predict(
        self,
        evidence: dict,
    ) -> dict[str, Any]:
        """
        Predict whether an email is benign or phishing.
        """

        if self.model is None:
            self.load_model()

        # Convert TRACE-AI evidence into the
        # standardized 20-feature vector.
        feature_data = extract_ml_features(
            evidence
        )

        features = feature_data["features"]

        # ----------------------------------------------------
        # Model prediction
        # ----------------------------------------------------

        prediction = self.model.predict(
            [features]
        )[0]

        # ----------------------------------------------------
        # Probability
        # ----------------------------------------------------

        probabilities = self.model.predict_proba(
            [features]
        )[0]

        benign_probability = float(
            probabilities[0]
        )

        phishing_probability = float(
            probabilities[1]
        )

        # ----------------------------------------------------
        # Classification
        # ----------------------------------------------------

        if int(prediction) == 1:
            classification = "PHISHING"
            confidence = phishing_probability
        else:
            classification = "BENIGN"
            confidence = benign_probability

        # ----------------------------------------------------
        # Confidence level
        # ----------------------------------------------------

        confidence_percentage = round(
            confidence * 100,
            2
        )

        if confidence >= 0.90:
            confidence_level = "VERY HIGH"

        elif confidence >= 0.75:
            confidence_level = "HIGH"

        elif confidence >= 0.60:
            confidence_level = "MEDIUM"

        else:
            confidence_level = "LOW"

        # ----------------------------------------------------
        # Feature contribution information
        # ----------------------------------------------------
        # Random Forest feature_importances_ tells us which
        # features were important to the trained model.
        #
        # IMPORTANT:
        # These are model-level feature importances, not a
        # mathematically exact explanation of this individual
        # email's prediction.

        feature_importance = {}

        if hasattr(
            self.model,
            "feature_importances_"
        ):

            importances = (
                self.model.feature_importances_
            )

            for name, importance in zip(
                FEATURE_NAMES,
                importances
            ):
                feature_importance[name] = round(
                    float(importance),
                    6
                )

        # Sort most important features first.

        ranked_importance = sorted(
            feature_importance.items(),
            key=lambda item: item[1],
            reverse=True
        )

        top_features = [
            {
                "feature": name,
                "importance": importance
            }
            for name, importance
            in ranked_importance[:10]
        ]

        # ----------------------------------------------------
        # Result
        # ----------------------------------------------------

        return {
            "model": "TRACE-AI Random Forest",

            "prediction": int(prediction),

            "classification": classification,

            "confidence": confidence_percentage,

            "confidence_level": confidence_level,

            "probabilities": {
                "benign": round(
                    benign_probability * 100,
                    2
                ),
                "phishing": round(
                    phishing_probability * 100,
                    2
                )
            },

            "feature_count": len(features),

            "features": feature_data[
                "feature_map"
            ],

            "top_model_features": top_features,

            "model_path": str(
                self.model_path
            )
        }


# ============================================================
# CONVENIENCE FUNCTION
# ============================================================

def predict_email(
    evidence: dict,
) -> dict[str, Any]:
    """
    Convenience wrapper for ML prediction.
    """

    classifier = TRACEAIClassifier()

    return classifier.predict(
        evidence
    )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("\nTRACE-AI ML PREDICTION TEST")
    print("==========================")

    # Synthetic phishing-style evidence.
    # This is only a pipeline test.

    test_evidence = {

        "risk_assessment": {
            "risk_score": 95
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

    try:

        classifier = TRACEAIClassifier()

        result = classifier.predict(
            test_evidence
        )

        print("\nML RESULT")
        print("---------")

        print(
            f"Classification : "
            f"{result['classification']}"
        )

        print(
            f"Confidence     : "
            f"{result['confidence']}%"
        )

        print(
            f"Confidence     : "
            f"{result['confidence_level']}"
        )

        print(
            f"Benign         : "
            f"{result['probabilities']['benign']}%"
        )

        print(
            f"Phishing       : "
            f"{result['probabilities']['phishing']}%"
        )

        print(
            f"Features       : "
            f"{result['feature_count']}"
        )

        print("\nTop Model Features")
        print("------------------")

        for item in result[
            "top_model_features"
        ]:

            print(
                f"{item['feature']:<30}"
                f"{item['importance']:.6f}"
            )

    except Exception as error:

        print(
            "\nML prediction failed:"
        )

        print(error)