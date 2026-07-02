import joblib
import pandas as pd


class BehaviorPredictor:

    FEATURES = [
        "login_hour",
        "logout_hour",
        "failed_login",
        "process_start",
        "usb_insert",
        "usb_executable_run",
        "file_access"
    ]

    def __init__(self):

        self.model = joblib.load("ml/model.joblib")

    def predict(self, feature_vector):

        values = {
            feature: getattr(feature_vector, feature)
            for feature in self.FEATURES
        }

        df = pd.DataFrame([values])

        prediction = self.model.predict(df)[0]

        score = self.model.decision_function(df)[0]

        # Convert score to 0–100 confidence
        confidence = (score + 0.5) * 100
        confidence = max(0, min(confidence, 100))

        if prediction == -1:
            label = "ANOMALY"
        else:
            label = "NORMAL"

        return label, round(confidence, 2)