import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest


class BehaviorTrainer:

    FEATURES = [
        "login_hour",
        "logout_hour",
        "failed_login",
        "process_start",
        "usb_insert",
        "usb_executable_run",
        "file_access"
    ]

    def train(
        self,
        dataset_path="data/ml_dataset.csv",
        model_path="ml/model.joblib"
    ):

        # Load dataset
        data = pd.read_csv(dataset_path)

        # Ensure required columns exist
        missing = [
            feature
            for feature in self.FEATURES
            if feature not in data.columns
        ]

        if missing:
            raise ValueError(
                f"Dataset missing columns: {missing}"
            )

        # Select only ML features
        X = data[self.FEATURES]

        # Train Isolation Forest
        model = IsolationForest(
            n_estimators=300,
            contamination=0.33,
            random_state=42
        )

        model.fit(X)

        # Save model
        joblib.dump(model, model_path)

        print(f"Model saved to {model_path}")