import argparse
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Training dan evaluasi model SVM untuk deteksi anomali."
    )
    parser.add_argument(
        "--data",
        default="dataset_svm.csv",
        help="Path file dataset CSV (default: dataset_svm.csv).",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.4,
        help="Proporsi data testing (default: 0.4, berarti split 60:40).",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Seed agar hasil split konsisten.",
    )
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.exists():
        raise FileNotFoundError(f"File dataset tidak ditemukan: {data_path}")

    df = pd.read_csv(data_path)
    if "numeric_label" not in df.columns:
        raise ValueError("Kolom target `numeric_label` tidak ditemukan di dataset.")

    X = df.drop(columns=["numeric_label"])
    y = df["numeric_label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )

    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "svm",
                SVC(
                    kernel="rbf",
                    C=1.0,
                    gamma="scale",
                    class_weight="balanced",
                    random_state=args.random_state,
                ),
            ),
        ]
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
    rec = recall_score(y_test, y_pred, average="macro", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)

    print("=== Evaluasi Utama ===")
    print(f"Accuracy            : {acc:.2f}")
    print(f"Precision (macro)   : {prec:.2f}")
    print(f"Recall (macro)      : {rec:.2f}")
    print(f"F1-Score (macro)    : {f1:.2f}\n")

    label_names = ["normal", "anomali"]
    print("=== Classification Report ===")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=label_names,
            digits=2,
            zero_division=0,
        )
    )


if __name__ == "__main__":
    main()