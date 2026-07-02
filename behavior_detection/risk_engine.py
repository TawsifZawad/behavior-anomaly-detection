class RiskEngine:

    RISK_RULES = {
        "login_hour": (20, "Unusual login hour"),
        "logout_hour": (10, "Unusual logout hour"),
        "failed_login": (40, "Failed login attempts"),
        "process_start": (10, "Different process activity"),
        "file_access": (10, "Different file access activity"),
        "usb_insert": (20, "USB activity detected"),
        "usb_executable_run": (40, "Executable launched from USB")
    }

    def calculate(self, comparison):

        """
        Calculate risk score based on
        behavior comparison.
        """

        score = 0
        reasons = []

        for feature, value in comparison.items():

            if value["status"] == "normal":
                continue

            if feature not in self.RISK_RULES:
                continue

            risk_score, reason = self.RISK_RULES[feature]

            score += risk_score
            reasons.append(reason)

        return score, reasons