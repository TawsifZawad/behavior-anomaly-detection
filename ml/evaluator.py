import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


class ModelEvaluator:

    FEATURES = [
        "login_hour",
        "logout_hour",
        "failed_login",
        "process_start",
        "usb_insert",
        "usb_executable_run",
        "file_access"
    ]

    def evaluate(
        self,
        dataset_path="data/ml_dataset.csv",
        model_path="ml/model.joblib"
    ):

        # Load dataset
        data = pd.read_csv(dataset_path)

        # Ground truth
        y_true = data["label"]

        # Use the same feature order as trainer.py
        X = data[self.FEATURES]

        # Load trained model
        model = joblib.load(model_path)

        # Predict
        prediction = model.predict(X)

        # Convert Isolation Forest output
        y_pred = [
            1 if value == -1 else 0
            for value in prediction
        ]

        print("\n===== Model Evaluation =====")

        print(f"Accuracy  : {accuracy_score(y_true, y_pred):.4f}")
        print(f"Precision : {precision_score(y_true, y_pred, zero_division=0):.4f}")
        print(f"Recall    : {recall_score(y_true, y_pred, zero_division=0):.4f}")
        print(f"F1 Score  : {f1_score(y_true, y_pred, zero_division=0):.4f}")

        print("\nConfusion Matrix")
        print(confusion_matrix(y_true, y_pred))

        print("\nClassification Report")
        print(
            classification_report(
                y_true,
                y_pred,
                target_names=["NORMAL", "ANOMALY"],
                zero_division=0
            )
        )