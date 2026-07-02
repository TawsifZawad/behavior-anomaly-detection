import json
import os
from datetime import datetime


class AlertManager:

    def __init__(self):

        os.makedirs("alerts", exist_ok=True)

    def create_alert(
        self,
        username,
        risk_score,
        risk_level,
        ml_prediction,
        final_status,
        reasons,
        correlations=None
    ):

        if correlations is None:
            correlations = []

        timestamp = datetime.now()

        alert = {

            "timestamp": timestamp.isoformat(),

            "username": username,

            "risk_score": risk_score,

            "risk_level": risk_level,

            "ml_prediction": ml_prediction,

            "final_status": final_status,

            "reasons": reasons,

            "correlations": correlations

        }

        filename = (
            f"alerts/"
            f"{username}_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        )

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                alert,
                file,
                indent=4
            )

        print("\nAlert saved.")
        print(filename)