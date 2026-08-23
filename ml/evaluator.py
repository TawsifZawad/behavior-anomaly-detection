import os

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

from models.feature_vector import ML_MODEL_FEATURES
from config.settings import ML_EVAL_FILE
from reporting.report_generator import ReportGenerator


class ModelEvaluator:

    # Evaluate on the same behavioral features the model was trained on.
    FEATURES = ML_MODEL_FEATURES

    def evaluate(
        self,
        dataset_path=ML_EVAL_FILE,
        model_path="ml/model.joblib"
    ):

        # Evaluate on a held-out set that the model never trained on:
        # real normal sessions (label 0) plus attack sessions replayed
        # from EVTX samples (label 1). This keeps the metrics honest.
        if not os.path.exists(dataset_path):
            print(
                f"\nEvaluation skipped: {dataset_path} not found. "
                f"Build it with scripts/replay_attack_samples.py."
            )
            return

        if not os.path.exists(model_path):
            print(
                f"\nEvaluation skipped: model {model_path} not found."
            )
            return

        data = pd.read_csv(dataset_path)

        if "label" not in data.columns:
            print(
                "\nEvaluation skipped: eval dataset has no 'label' column."
            )
            return

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

        # Continuous anomaly score for the ROC curve. decision_function
        # returns higher values for MORE normal points, so negate it to
        # get a score where higher = more anomalous (label 1).
        y_score = [-value for value in model.decision_function(X)]

        print("\n===== Model Evaluation =====")

        print(f"Accuracy  : {accuracy_score(y_true, y_pred):.4f}")
        print(f"Precision : {precision_score(y_true, y_pred, zero_division=0):.4f}")
        print(f"Recall    : {recall_score(y_true, y_pred, zero_division=0):.4f}")
        print(f"F1 Score  : {f1_score(y_true, y_pred, zero_division=0):.4f}")

        print("\nConfusion Matrix")
        print(confusion_matrix(y_true, y_pred, labels=[0, 1]))

        print("\nClassification Report")
        print(
            classification_report(
                y_true,
                y_pred,
                labels=[0, 1],
                target_names=["NORMAL", "ANOMALY"],
                zero_division=0
            )
        )

        # Persist thesis-ready artifacts: metrics.json, confusion_matrix
        # .png and roc_curve.png under reports/.
        ReportGenerator().generate(y_true, y_pred, y_score)
