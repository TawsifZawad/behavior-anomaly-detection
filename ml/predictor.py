import os

import joblib
import pandas as pd

from models.feature_vector import ML_MODEL_FEATURES


# Readable label per behavioral feature, for explaining WHICH behaviour
# deviated in an alert.
BEHAVIOR_LABELS = {
    "login_hour": "login time",
    "logout_hour": "logout time",
    "session_span": "session length",
    "off_hours_ratio": "off-hours activity",
    "weekend_activity": "weekend activity",
    "event_rate": "activity rate",
    "active_hours": "active-hours spread",
    "process_start": "process volume",
    "file_access": "file activity",
    "distinct_processes": "program variety",
    "file_to_process_ratio": "file/process ratio",
    "failed_login": "failed logins",
    "login_attempts": "login attempts",
    "off_hours_logon": "off-hours logins",
    "distinct_file_types": "file-type variety",
    "usb_events": "USB device use",
    "removable_file_events": "removable-media activity",
    "distinct_ips": "network sources",
}


class BehaviorPredictor:

    # Must match the features the model was trained on (behavioral only).
    FEATURES = ML_MODEL_FEATURES

    def __init__(self, model_path="ml/model.joblib"):

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found at {model_path}. "
                f"Run training first (main.py or BehaviorTrainer.train())."
            )

        self.model = joblib.load(model_path)

    def predict(self, feature_vector):

        values = {
            feature: getattr(feature_vector, feature)
            for feature in self.FEATURES
        }

        df = pd.DataFrame([values])

        prediction = self.model.predict(df)[0]

        # decision_function: > 0 normal, < 0 anomalous; magnitude = how
        # far from the boundary. Map to an interpretable 0-100 anomaly
        # score where the decision boundary sits at 50 (higher = more
        # anomalous), so an alert reads "anomaly score 78/100".
        raw = self.model.decision_function(df)[0]
        anomaly_score = 50.0 - raw * 250.0
        anomaly_score = max(0.0, min(100.0, anomaly_score))

        label = "ANOMALY" if prediction == -1 else "NORMAL"

        return label, round(anomaly_score, 1)

    def behavioral_deviations(self, feature_vector, top=6, threshold=1.5):
        """
        Explain the ML verdict: which behavioral dimensions deviate most
        from the learned normal. Reuses the model's own StandardScaler
        (fitted on normal behaviour) to compute a z-score per feature —
        so "off-hours activity 3.4σ above usual" is the model's own
        reasoning, not a separate heuristic.

        Returns readable strings, most-deviant first.
        """
        try:
            scaler = self.model.named_steps["standardscaler"]
        except (AttributeError, KeyError):
            return []

        deviations = []
        for i, feature in enumerate(self.FEATURES):
            value = float(getattr(feature_vector, feature, 0) or 0)
            mean = float(scaler.mean_[i])
            scale = float(scaler.scale_[i]) or 1.0
            z = (value - mean) / scale

            if abs(z) < threshold:
                continue

            label = BEHAVIOR_LABELS.get(feature, feature)
            arrow = "up" if z > 0 else "down"
            deviations.append({
                "label": label,
                "z": round(z, 1),
                "value": round(value, 2),
                "usual": round(mean, 2),
                "direction": arrow,
                "text": (
                    f"{label} {arrow} "
                    f"({value:.1f} vs usual {mean:.1f}, {z:+.1f} SD)"
                ),
            })

        deviations.sort(key=lambda d: abs(d["z"]), reverse=True)
        return deviations[:top]
