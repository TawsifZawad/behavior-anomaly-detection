import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

import joblib


class ModelEvaluator:

    def evaluate(
        self,
        dataset_path="data/ml_dataset.csv",
        model_path="ml/model.joblib"
    ):

        # Load dataset
        data = pd.read_csv(dataset_path)

        # Ground truth labels
        y_true = data["label"]

        # Feature columns
        X = data.drop(
            columns=["username", "label"]
        )

        # Load model
        model = joblib.load(model_path)

        # Isolation Forest prediction
        prediction = model.predict(X)

        # Convert prediction
        # 1  -> Normal (0)
        # -1 -> Anomaly (1)

        y_pred = []

        for value in prediction:

            if value == -1:
                y_pred.append(1)
            else:
                y_pred.append(0)

        print("\n===== Model Evaluation =====")

        print(
            f"Accuracy  : {accuracy_score(y_true, y_pred):.4f}"
        )

        print(
            f"Precision : {precision_score(y_true, y_pred, zero_division=0):.4f}"
        )

        print(
            f"Recall    : {recall_score(y_true, y_pred, zero_division=0):.4f}"
        )

        print(
            f"F1 Score  : {f1_score(y_true, y_pred, zero_division=0):.4f}"
        )

        print("\nConfusion Matrix")

        print(confusion_matrix(y_true, y_pred))