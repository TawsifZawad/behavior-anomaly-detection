import csv
import json
import os
from datetime import datetime

from config.settings import ALERTS_DIR, ALERTS_CSV


class AlertManager:

    CSV_HEADER = [
        "timestamp",
        "username",
        "risk_score",
        "risk_level",
        "ml_prediction",
        "final_status",
        "top_correlation",
        "mitre",
        "reasons",
        "indicators",
        "ml_score",
        "ml_deviations",
    ]

    def __init__(self):

        os.makedirs(ALERTS_DIR, exist_ok=True)

    def create_alert(
        self,
        username,
        risk_score,
        risk_level,
        ml_prediction,
        final_status,
        reasons,
        correlations=None,
        indicators=None,
        ml_score=None,
        ml_deviations=None
    ):

        if correlations is None:
            correlations = []

        if indicators is None:
            indicators = []

        if ml_deviations is None:
            ml_deviations = []

        timestamp = datetime.now()

        alert = {

            "timestamp": timestamp.isoformat(),

            "username": username,

            "risk_score": risk_score,

            "risk_level": risk_level,

            "ml_prediction": ml_prediction,

            "ml_score": ml_score,

            "ml_deviations": ml_deviations,

            "final_status": final_status,

            "reasons": reasons,

            "indicators": indicators,

            "correlations": correlations

        }

        filename = (
            f"{ALERTS_DIR}/"
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

        self._append_csv(alert)

        print("\nAlert saved.")
        print(filename)

    def _append_csv(self, alert):
        """
        Append a flattened one-line record to the rolling alerts CSV so
        the dashboard and any spreadsheet tool can read the alert history
        without parsing every JSON file.
        """

        correlations = alert.get("correlations") or []

        top_correlation = correlations[0]["name"] if correlations else ""

        mitre = sorted({
            technique
            for c in correlations
            for technique in c.get("mitre", [])
        })

        row = {
            "timestamp": alert["timestamp"],
            "username": alert["username"],
            "risk_score": alert["risk_score"],
            "risk_level": alert["risk_level"],
            "ml_prediction": alert["ml_prediction"],
            "final_status": alert["final_status"],
            "top_correlation": top_correlation,
            "mitre": "; ".join(mitre),
            "reasons": "; ".join(alert.get("reasons") or []),
            "indicators": " || ".join(alert.get("indicators") or []),
            "ml_score": alert.get("ml_score") if alert.get("ml_score")
            is not None else "",
            "ml_deviations": " || ".join(alert.get("ml_deviations") or []),
        }

        # If an older CSV exists with a different column set, start it
        # over so the header and rows stay aligned.
        if os.path.exists(ALERTS_CSV):
            with open(ALERTS_CSV, newline="", encoding="utf-8") as f:
                existing_header = next(csv.reader(f), None)
            if existing_header != self.CSV_HEADER:
                os.remove(ALERTS_CSV)

        write_header = not os.path.exists(ALERTS_CSV)

        with open(ALERTS_CSV, "a", newline="", encoding="utf-8") as file:

            writer = csv.DictWriter(file, fieldnames=self.CSV_HEADER)

            if write_header:
                writer.writeheader()

            writer.writerow(row)
