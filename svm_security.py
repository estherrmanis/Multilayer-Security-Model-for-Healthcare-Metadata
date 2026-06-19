from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC


ATTACK_PATTERNS: Dict[str, List[str]] = {
    "XSS": ["<script", "onerror", "onload", "iframe", "svg", "javascript:", "alert("],
    "SQL Injection": [
        "union select",
        "' or '1'='1",
        "sleep(",
        " or 1=1",
        "select ",
        "insert ",
        "drop ",
        "sqli",
    ],
    "Bruteforce": ["password", "letmein", "qwerty", "123123", "123456", "admin123"],
}


def detect_attack_type(text: str) -> str:
    probe = text.lower()
    scores = {}
    for attack_name, keywords in ATTACK_PATTERNS.items():
        scores[attack_name] = sum(1 for kw in keywords if kw in probe)
    best_attack = max(scores, key=scores.get)
    return best_attack if scores[best_attack] > 0 else "Anomali Tidak Diketahui"


@dataclass
class PredictionResult:
    is_anomaly: bool
    label: int
    confidence: float
    detected_attack: str


class SVMAnomalyDetector:
    def __init__(self, dataset_path: str = "dataset_svm.csv", random_state: int = 42):
        self.dataset_path = Path(dataset_path)
        self.random_state = random_state
        self.feature_columns: List[str] = []
        self.model: Pipeline | None = None
        self._fit()

    def _fit(self) -> None:
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"Dataset tidak ditemukan: {self.dataset_path}")

        df = pd.read_csv(self.dataset_path)
        if "numeric_label" not in df.columns:
            raise ValueError("Kolom numeric_label tidak ditemukan pada dataset.")

        X = df.drop(columns=["numeric_label"])
        y = df["numeric_label"].astype(int)
        self.feature_columns = list(X.columns)

        self.model = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "svm",
                    SVC(
                        kernel="rbf",
                        C=1.0,
                        gamma="scale",
                        class_weight="balanced",
                        probability=True,
                        random_state=self.random_state,
                    ),
                ),
            ]
        )
        self.model.fit(X, y)

    def _vectorize_login_input(self, username: str, password: str) -> pd.DataFrame:
        text = f"{username} {password}".lower()
        tokens = text.split()

        vector = {}
        for col in self.feature_columns:
            token_count = text.count(col)
            if token_count > 0:
                vector[col] = float(token_count)
            elif col in tokens:
                vector[col] = 1.0
            else:
                vector[col] = 0.0

        return pd.DataFrame([vector], columns=self.feature_columns)

    def predict_login(self, username: str, password: str) -> PredictionResult:
        if self.model is None:
            raise RuntimeError("Model SVM belum diinisialisasi.")

        features = self._vectorize_login_input(username, password)
        pred = int(self.model.predict(features)[0])
        probas = self.model.predict_proba(features)[0]
        confidence = float(max(probas))
        attack_type = detect_attack_type(f"{username} {password}") if pred == 1 else "Normal"

        return PredictionResult(
            is_anomaly=pred == 1,
            label=pred,
            confidence=confidence,
            detected_attack=attack_type,
        )
