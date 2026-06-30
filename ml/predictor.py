import joblib
import pandas as pd


class BehaviorPredictor:

    def __init__(self):

        self.model = joblib.load("ml/model.joblib")

    def predict(self, feature_vector):

        # Feature order MUST match trainer.py
        df = pd.DataFrame([{
            "login_hour": feature_vector.login_hour,
            "logout_hour": feature_vector.logout_hour,
            "failed_login": feature_vector.failed_login,
            "process_start": feature_vector.process_start,
            "usb_insert": feature_vector.usb_insert,
            "file_access": feature_vector.file_access
        }])

        prediction = self.model.predict(df)[0]

        score = self.model.decision_function(df)[0]

        # Convert score to 0-100 confidence
        confidence = (score + 0.5) * 100
        confidence = max(0, min(confidence, 100))

        if prediction == -1:
            label = "ANOMALY"
        else:
            label = "NORMAL"

        return label, confidence