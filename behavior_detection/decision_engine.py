class DecisionEngine:

    def decide(
        self,
        risk_score,
        ml_prediction,
        correlations=None
    ):

        if correlations is None:
            correlations = []

        # =====================================
        # Correlation Decision
        # =====================================

        severities = {
            item["severity"]
            for item in correlations
        }

        if "CRITICAL" in severities:
            return "CRITICAL"

        if "HIGH" in severities:
            return "SUSPICIOUS"

        # =====================================
        # Hybrid Decision
        # =====================================

        if risk_score >= 70 and ml_prediction == "ANOMALY":
            return "CRITICAL"

        if risk_score < 30 and ml_prediction == "NORMAL":
            return "SAFE"

        if risk_score >= 70:
            return "SUSPICIOUS"

        if ml_prediction == "ANOMALY":
            return "REVIEW"

        return "NORMAL"