class BehaviorAnalyzer:

    def get_risk_level(self, score):

        if score <= 20:
            return "LOW"

        elif score <= 50:
            return "MEDIUM"

        return "HIGH"
