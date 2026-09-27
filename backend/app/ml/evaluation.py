"""
TRACE-AI ML Model Evaluation & Study Engine
Provides dynamic metrics, confusion matrix, ROC/PR curves, and parameter tuning.
"""

from pathlib import Path
from typing import Any, Dict, List
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    roc_curve,
    precision_recall_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parents[2]
DATASET_PATH = BASE_DIR / "datasets" / "processed" / "spamassassin_dataset.csv"
MODEL_PATH = BASE_DIR / "app" / "ml" / "text_model.pkl"


class ModelEvaluator:
    """
    Evaluates the SpamAssassin text classifier and allows live threshold tuning,
    confusion matrix analysis, and parameter studying.
    """

    def __init__(self):
        self.model: Pipeline | None = None
        self.X_train: pd.Series | None = None
        self.X_test: pd.Series | None = None
        self.y_train: pd.Series | None = None
        self.y_test: pd.Series | None = None
        self.test_probabilities: np.ndarray | None = None
        self.dataset_stats: Dict[str, Any] = {}
        self.top_spam_features: List[Dict[str, Any]] = []
        self.top_ham_features: List[Dict[str, Any]] = []
        self.roc_curve_data: List[Dict[str, float]] = []
        self.pr_curve_data: List[Dict[str, float]] = []
        self.roc_auc: float = 0.0
        self._is_initialized = False

    def load_and_prep_data(self, test_size: float = 0.20, random_state: int = 42):
        if not DATASET_PATH.exists():
            raise FileNotFoundError(f"Dataset not found at: {DATASET_PATH}")

        df = pd.read_csv(DATASET_PATH)
        df = df[df["label"].isin([0, 1])].copy()
        df["text"] = df["text"].fillna("").astype(str)
        df = df[df["text"].str.strip() != ""]
        df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)

        total_samples = len(df)
        ham_count = int((df["label"] == 0).sum())
        spam_count = int((df["label"] == 1).sum())

        self.dataset_stats = {
            "total_samples": total_samples,
            "ham_count": ham_count,
            "spam_count": spam_count,
            "ham_ratio": round(ham_count / total_samples, 4) if total_samples else 0,
            "spam_ratio": round(spam_count / total_samples, 4) if total_samples else 0,
            "test_size": test_size,
            "train_samples": int(total_samples * (1 - test_size)),
            "test_samples": int(total_samples * test_size),
        }

        X = df["text"]
        y = df["label"]

        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

    def train_or_load_model(self, force_retrain: bool = False, max_features: int = 100000):
        # Attempt to load model if not forcing retrain
        loaded = False
        if not force_retrain and MODEL_PATH.exists():
            try:
                self.model = joblib.load(MODEL_PATH)
                loaded = True
            except Exception:
                loaded = False

        if not loaded:
            # Build and train fresh pipeline
            tfidf = TfidfVectorizer(
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.98,
                max_features=max_features,
                sublinear_tf=True,
                lowercase=True,
                stop_words="english",
            )
            classifier = LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                random_state=42,
            )
            self.model = Pipeline([
                ("tfidf", tfidf),
                ("classifier", classifier),
            ])
            self.model.fit(self.X_train, self.y_train)
            try:
                joblib.dump(self.model, MODEL_PATH)
            except Exception:
                pass

        # Compute probabilities on test set
        self.test_probabilities = self.model.predict_proba(self.X_test)[:, 1]
        self.roc_auc = float(roc_auc_score(self.y_test, self.test_probabilities))

        # Precompute ROC Curve
        fpr_arr, tpr_arr, _ = roc_curve(self.y_test, self.test_probabilities)
        step = max(1, len(fpr_arr) // 30)
        self.roc_curve_data = [
            {"fpr": round(float(fpr_arr[i]), 4), "tpr": round(float(tpr_arr[i]), 4)}
            for i in range(0, len(fpr_arr), step)
        ]
        if self.roc_curve_data[-1] != {"fpr": 1.0, "tpr": 1.0}:
            self.roc_curve_data.append({"fpr": 1.0, "tpr": 1.0})

        # Precompute PR Curve
        p_arr, r_arr, _ = precision_recall_curve(self.y_test, self.test_probabilities)
        p_step = max(1, len(p_arr) // 30)
        self.pr_curve_data = [
            {"recall": round(float(r_arr[i]), 4), "precision": round(float(p_arr[i]), 4)}
            for i in range(0, len(p_arr), p_step)
        ]

        # Extract top feature coefficients
        vectorizer = self.model["tfidf"]
        classifier = self.model["classifier"]
        feature_names = vectorizer.get_feature_names_out()
        coefficients = classifier.coef_[0]

        top_spam_indices = coefficients.argsort()[-20:][::-1]
        top_ham_indices = coefficients.argsort()[:20]

        self.top_spam_features = [
            {"feature": str(feature_names[idx]), "weight": round(float(coefficients[idx]), 4)}
            for idx in top_spam_indices
        ]
        self.top_ham_features = [
            {"feature": str(feature_names[idx]), "weight": round(float(coefficients[idx]), 4)}
            for idx in top_ham_indices
        ]

        self._is_initialized = True

    def initialize(self):
        if not self._is_initialized:
            self.load_and_prep_data()
            self.train_or_load_model()

    def evaluate_at_threshold(self, threshold: float = 0.5) -> Dict[str, Any]:
        self.initialize()
        threshold = max(0.01, min(0.99, float(threshold)))

        # Predictions at this threshold
        y_pred = (self.test_probabilities >= threshold).astype(int)
        y_true = np.array(self.y_test)

        # Confusion Matrix: [[TN, FP], [FN, TP]]
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1])

        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        return {
            "threshold": round(threshold, 3),
            "metrics": {
                "accuracy": round(float(acc), 4),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1_score": round(float(f1), 4),
                "specificity": round(float(specificity), 4),
                "roc_auc": round(float(self.roc_auc), 4),
                "fpr": round(float(fpr), 4),
                "fnr": round(float(fnr), 4),
            },
            "confusion_matrix": {
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "matrix": [[tn, fp], [fn, tp]],
            },
            "operating_point": {
                "threshold": round(threshold, 3),
                "fpr": round(float(fpr), 4),
                "tpr": round(float(rec), 4),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
            },
            "roc_curve": self.roc_curve_data,
            "pr_curve": self.pr_curve_data,
            "top_spam_features": self.top_spam_features,
            "top_ham_features": self.top_ham_features,
            "dataset_stats": self.dataset_stats,
        }

    def predict_custom_text(self, subject: str, body: str, threshold: float = 0.5) -> Dict[str, Any]:
        self.initialize()
        combined = f"Subject: {subject}\n\n{body}".strip()
        if not combined:
            return {"error": "Empty text provided"}

        prob_spam = float(self.model.predict_proba([combined])[0][1])
        prob_ham = 1.0 - prob_spam
        is_spam = prob_spam >= threshold

        confidence = prob_spam if is_spam else prob_ham

        return {
            "classification": "SPAM" if is_spam else "HAM",
            "is_threat": is_spam,
            "confidence": round(confidence * 100, 2),
            "probabilities": {
                "spam": round(prob_spam, 4),
                "ham": round(prob_ham, 4),
            },
            "threshold_used": threshold,
            "length": len(combined),
        }


# Singleton instance
evaluator = ModelEvaluator()
