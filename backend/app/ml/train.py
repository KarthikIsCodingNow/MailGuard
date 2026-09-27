from pathlib import Path
from typing import Any

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

from app.ml.dataset import (
    FEATURE_NAMES,
    create_seed_dataset,
    dataset_summary,
)


# ============================================================
# TRACE-AI ML TRAINING PIPELINE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model.pkl"


def train_model(
    X: list[list[float]],
    y: list[int],
) -> RandomForestClassifier:
    """
    Train the TRACE-AI Random Forest classifier.
    """

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced",
    )

    model.fit(X, y)

    return model


def save_model(
    model: RandomForestClassifier,
    path: Path = MODEL_PATH,
) -> None:
    """
    Save the trained model to disk.
    """

    joblib.dump(model, path)


def evaluate_model(
    model: RandomForestClassifier,
    X_test: list[list[float]],
    y_test: list[int],
) -> dict[str, Any]:
    """
    Evaluate the trained model.

    The current seed dataset is synthetic and extremely small.
    Therefore, these metrics are only used to verify that the
    training pipeline works.
    """

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
    )

    report = classification_report(
        y_test,
        predictions,
        zero_division=0,
    )

    return {
        "accuracy": float(accuracy),
        "confusion_matrix": matrix.tolist(),
        "classification_report": report,
    }


def print_feature_importance(
    model: RandomForestClassifier,
) -> None:
    """
    Display the importance of each feature.
    """

    importances = model.feature_importances_

    ranked_features = sorted(
        zip(FEATURE_NAMES, importances),
        key=lambda item: item[1],
        reverse=True,
    )

    print("\nFEATURE IMPORTANCE")
    print("==================")

    for name, importance in ranked_features:
        print(
            f"{name:<30} "
            f"{importance:.4f}"
        )


def main() -> None:

    print("\nTRACE-AI ML TRAINING")
    print("===================")

    # --------------------------------------------------------
    # 1. Create dataset
    # --------------------------------------------------------

    X, y = create_seed_dataset()

    summary = dataset_summary(
        X,
        y,
    )

    print(
        f"\nSamples: {summary['samples']}"
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
        "\nWARNING:"
    )

    print(
        "The current dataset is synthetic and contains "
        "only six samples."
    )

    print(
        "This training run is for pipeline verification only."
    )

    # --------------------------------------------------------
    # 2. Split dataset
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.33,
        random_state=42,
        stratify=y,
    )

    print(
        f"\nTraining samples: {len(X_train)}"
    )

    print(
        f"Testing samples: {len(X_test)}"
    )

    # --------------------------------------------------------
    # 3. Train model
    # --------------------------------------------------------

    print("\nTraining Random Forest...")

    model = train_model(
        X_train,
        y_train,
    )

    print(
        "Training completed."
    )

    # --------------------------------------------------------
    # 4. Evaluate
    # --------------------------------------------------------

    results = evaluate_model(
        model,
        X_test,
        y_test,
    )

    print("\nMODEL EVALUATION")
    print("================")

    print(
        f"Accuracy: "
        f"{results['accuracy']:.2f}"
    )

    print("\nConfusion Matrix:")

    for row in results["confusion_matrix"]:
        print(row)

    print("\nClassification Report:")

    print(
        results["classification_report"]
    )

    # --------------------------------------------------------
    # 5. Feature importance
    # --------------------------------------------------------

    print_feature_importance(
        model
    )

    # --------------------------------------------------------
    # 6. Save model
    # --------------------------------------------------------

    save_model(
        model
    )

    print(
        f"\nModel saved to:"
        f"\n{MODEL_PATH}"
    )

    print(
        "\nTRACE-AI ML TRAINING COMPLETE"
    )


if __name__ == "__main__":
    main()