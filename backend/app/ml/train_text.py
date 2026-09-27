from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# ============================================================
# TRACE-AI REAL EMAIL TEXT ML TRAINING
# ============================================================
#
# Dataset:
#   SpamAssassin processed email corpus
#
# Labels:
#   0 = HAM / BENIGN
#   1 = SPAM
#
# Pipeline:
#
#   Email text
#       ↓
#   TF-IDF
#       ↓
#   Logistic Regression
#       ↓
#   Classification
#
# IMPORTANT:
# This is a real-world spam/ham baseline.
# Spam is NOT equivalent to phishing.
#
# The model will later be evaluated separately and then
# combined with TRACE-AI forensic evidence.
# ============================================================


BASE_DIR = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "spamassassin_dataset.csv"
)

MODEL_PATH = (
    BASE_DIR
    / "app"
    / "ml"
    / "text_model.pkl"
)


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset() -> pd.DataFrame:
    """
    Load the processed email dataset.
    """

    if not DATASET_PATH.exists():

        raise FileNotFoundError(
            f"Dataset not found:\n"
            f"{DATASET_PATH}\n\n"
            f"Run:\n"
            f"python -m app.ml.preprocess"
        )

    df = pd.read_csv(
        DATASET_PATH
    )

    required_columns = {
        "text",
        "label"
    }

    missing_columns = (
        required_columns
        - set(df.columns)
    )

    if missing_columns:

        raise ValueError(
            "Dataset is missing required "
            f"columns: {missing_columns}"
        )

    return df


# ============================================================
# CLEAN DATASET
# ============================================================

def clean_dataset(
    df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Remove unusable rows and exact duplicate emails.
    """

    df = df.copy()

    # Keep only valid labels.

    df = df[
        df["label"].isin(
            [0, 1]
        )
    ]

    # Convert text to strings.

    df["text"] = (
        df["text"]
        .fillna("")
        .astype(str)
    )

    # Remove empty messages.

    df = df[
        df["text"].str.strip() != ""
    ]

    # Remove exact duplicates.

    before_duplicates = len(df)

    df = df.drop_duplicates(
        subset=["text"]
    )

    removed_duplicates = (
        before_duplicates
        - len(df)
    )

    print(
        f"\nExact duplicate emails removed: "
        f"{removed_duplicates}"
    )

    return df.reset_index(
        drop=True
    )


# ============================================================
# BUILD MODEL
# ============================================================

def build_model() -> Pipeline:
    """
    Build the TF-IDF + Logistic Regression pipeline.
    """

    tfidf = TfidfVectorizer(

        # Word unigrams and bigrams.

        ngram_range=(
            1,
            2
        ),

        # Ignore extremely rare terms.

        min_df=2,

        # Ignore extremely common terms.

        max_df=0.98,

        # Limit vocabulary size.

        max_features=100000,

        # Helps reduce the influence of very long
        # documents.

        sublinear_tf=True,

        # Lowercase text.

        lowercase=True,

        # Remove basic English stop words.

        stop_words="english"
    )

    classifier = LogisticRegression(

        max_iter=2000,

        class_weight="balanced",

        random_state=42
    )

    model = Pipeline([

        (
            "tfidf",
            tfidf
        ),

        (
            "classifier",
            classifier
        )
    ])

    return model


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(
    model: Pipeline,
    X_test: pd.Series,
    y_test: pd.Series,
) -> dict[str, Any]:
    """
    Evaluate the trained text classifier.
    """

    predictions = model.predict(
        X_test
    )

    probabilities = (
        model.predict_proba(
            X_test
        )[:, 1]
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        probabilities
    )

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    report = classification_report(
        y_test,
        predictions,
        target_names=[
            "HAM",
            "SPAM"
        ],
        zero_division=0
    )

    return {

        "accuracy": float(
            accuracy
        ),

        "precision": float(
            precision
        ),

        "recall": float(
            recall
        ),

        "f1": float(
            f1
        ),

        "roc_auc": float(
            roc_auc
        ),

        "confusion_matrix": (
            matrix.tolist()
        ),

        "classification_report": (
            report
        )
    }


# ============================================================
# DISPLAY TOP FEATURES
# ============================================================

def print_top_features(
    model: Pipeline,
    top_n: int = 20,
) -> None:
    """
    Display the strongest words/bigrams associated with
    HAM and SPAM according to the logistic regression model.
    """

    vectorizer = model[
        "tfidf"
    ]

    classifier = model[
        "classifier"
    ]

    feature_names = (
        vectorizer.get_feature_names_out()
    )

    coefficients = (
        classifier.coef_[0]
    )

    # Positive coefficient = SPAM direction.
    spam_indices = coefficients.argsort()[
        -top_n:
    ][::-1]

    # Negative coefficient = HAM direction.
    ham_indices = coefficients.argsort()[
        :top_n
    ]

    print(
        "\nTOP SPAM FEATURES"
    )

    print(
        "================="
    )

    for index in spam_indices:

        print(
            f"{feature_names[index]:<35}"
            f"{coefficients[index]:.4f}"
        )

    print(
        "\nTOP HAM FEATURES"
    )

    print(
        "================"
    )

    for index in ham_indices:

        print(
            f"{feature_names[index]:<35}"
            f"{coefficients[index]:.4f}"
        )


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(
    model: Pipeline,
) -> None:
    """
    Save the complete TF-IDF + Logistic Regression pipeline.
    """

    joblib.dump(
        model,
        MODEL_PATH
    )


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print(
        "\nTRACE-AI REAL EMAIL TEXT ML"
    )

    print(
        "==========================="
    )

    # --------------------------------------------------------
    # 1. Load
    # --------------------------------------------------------

    print(
        "\nLoading dataset..."
    )

    df = load_dataset()

    print(
        f"Raw samples: {len(df)}"
    )

    # --------------------------------------------------------
    # 2. Clean
    # --------------------------------------------------------

    df = clean_dataset(
        df
    )

    print(
        f"Usable samples: {len(df)}"
    )

    # --------------------------------------------------------
    # 3. Class distribution
    # --------------------------------------------------------

    benign_count = int(
        (df["label"] == 0).sum()
    )

    spam_count = int(
        (df["label"] == 1).sum()
    )

    print(
        f"HAM / BENIGN: {benign_count}"
    )

    print(
        f"SPAM:         {spam_count}"
    )

    # --------------------------------------------------------
    # 4. Prepare X and y
    # --------------------------------------------------------

    X = df["text"]

    y = df["label"]

    # --------------------------------------------------------
    # 5. Stratified train/test split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = (
        train_test_split(

            X,
            y,

            test_size=0.20,

            random_state=42,

            stratify=y
        )
    )

    print(
        f"\nTraining samples: "
        f"{len(X_train)}"
    )

    print(
        f"Testing samples:  "
        f"{len(X_test)}"
    )

    # --------------------------------------------------------
    # 6. Build model
    # --------------------------------------------------------

    print(
        "\nBuilding TF-IDF + Logistic Regression..."
    )

    model = build_model()

    # --------------------------------------------------------
    # 7. Train
    # --------------------------------------------------------

    print(
        "Training model..."
    )

    model.fit(
        X_train,
        y_train
    )

    print(
        "Training completed."
    )

    # --------------------------------------------------------
    # 8. Evaluate
    # --------------------------------------------------------

    print(
        "\nEvaluating model..."
    )

    results = evaluate_model(
        model,
        X_test,
        y_test
    )

    print(
        "\nMODEL PERFORMANCE"
    )

    print(
        "================="
    )

    print(
        f"Accuracy : "
        f"{results['accuracy']:.4f}"
    )

    print(
        f"Precision: "
        f"{results['precision']:.4f}"
    )

    print(
        f"Recall   : "
        f"{results['recall']:.4f}"
    )

    print(
        f"F1-score : "
        f"{results['f1']:.4f}"
    )

    print(
        f"ROC-AUC  : "
        f"{results['roc_auc']:.4f}"
    )

    # --------------------------------------------------------
    # 9. Confusion matrix
    # --------------------------------------------------------

    print(
        "\nCONFUSION MATRIX"
    )

    print(
        "================"
    )

    for row in results[
        "confusion_matrix"
    ]:

        print(
            row
        )

    # --------------------------------------------------------
    # 10. Classification report
    # --------------------------------------------------------

    print(
        "\nCLASSIFICATION REPORT"
    )

    print(
        "====================="
    )

    print(
        results[
            "classification_report"
        ]
    )

    # --------------------------------------------------------
    # 11. Feature analysis
    # --------------------------------------------------------

    print_top_features(
        model
    )

    # --------------------------------------------------------
    # 12. Save
    # --------------------------------------------------------

    save_model(
        model
    )

    print(
        "\nTEXT MODEL SAVED"
    )

    print(
        "================"
    )

    print(
        MODEL_PATH
    )

    print(
        "\nTRACE-AI REAL TEXT ML TRAINING COMPLETE"
    )


if __name__ == "__main__":
    main()