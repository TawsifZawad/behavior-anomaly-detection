import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from models.feature_vector import ML_MODEL_FEATURES
from config.settings import MIN_TRAINING_SAMPLES


class BehaviorTrainer:

    # The anomaly model learns only the behavioral / temporal / volume
    # features; rule-derived threat indicators are handled by the rule and
    # correlation engines.
    FEATURES = ML_MODEL_FEATURES

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

        # Isolation Forest models NORMAL behavior. Train ONLY on rows
        # labelled normal (label == 0); attack rows (label == 1) belong
        # to the evaluation set and must never enter training. Datasets
        # without a label column are assumed to be all-normal baselines.
        if "label" in data.columns:
            normal = data[data["label"] == 0]
        else:
            normal = data

        if len(normal) < MIN_TRAINING_SAMPLES:
            raise ValueError(
                f"Not enough normal samples to train: "
                f"{len(normal)} < {MIN_TRAINING_SAMPLES}"
            )

        # Select only ML features
        X = normal[self.FEATURES]

        # Standardize first so heterogeneous features contribute
        # comparably: high-magnitude counts (process/file volume) no
        # longer dominate the split selection over the 0/1 threat
        # indicators that actually matter. Scaler is saved with the model
        # as one pipeline, so prediction applies the same transform.
        model = make_pipeline(
            StandardScaler(),
            IsolationForest(
                n_estimators=300,
                contamination=0.02,
                random_state=42,
            ),
        )

        model.fit(X)

        # Save model (scaler + forest together)
        joblib.dump(model, model_path)

        print(
            f"Model trained on {len(normal)} normal samples "
            f"and saved to {model_path}"
        )
