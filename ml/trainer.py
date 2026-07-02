import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest


class BehaviorTrainer:

    def train(
        self,
        dataset_path="data/ml_dataset.csv",
        model_path="ml/model.joblib"
    ):

        # Load dataset
        data = pd.read_csv(dataset_path)

        # Remove username and label
        X = data.drop(
            columns=["username", "label"]
        )

        # Train model
        model = IsolationForest(
        n_estimators=200,
        contamination=0.33,
        random_state=42
        )

        model.fit(X)

        # Save model
        joblib.dump(model, model_path)

        print(f"Model saved to {model_path}")