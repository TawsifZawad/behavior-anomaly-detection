class DecisionEngine:

    def decide(
        self,
        risk_score,
        ml_prediction,
        correlations=None
    ):
        if correlations is None:
            correlations = []

        # Correlation rules have highest priority
        if correlations:
            return "CRITICAL"

        # Both systems agree
        if risk_score >= 70 and ml_prediction == "ANOMALY":
            return "CRITICAL"

        if risk_score < 30 and ml_prediction == "NORMAL":
            return "SAFE"

        # Only rule engine thinks suspicious
        if risk_score >= 70:
            return "SUSPICIOUS"

        # Only ML thinks suspicious
        if ml_prediction == "ANOMALY":
            return "REVIEW"

        return "NORMAL"