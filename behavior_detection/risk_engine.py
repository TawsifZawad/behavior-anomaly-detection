class RiskEngine:

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

            if feature == "login_hour":
                score += 20
                reasons.append("Unusual login hour")

            elif feature == "logout_hour":
                score += 10
                reasons.append("Unusual logout hour")

            elif feature == "failed_login":
                score += 40
                reasons.append("Failed login attempts")

            elif feature == "process_start":
                score += 10
                reasons.append("Different process activity")

            elif feature == "file_access":
                score += 10
                reasons.append("Different file access activity")

            elif feature == "usb_insert":
                score += 20
                reasons.append("USB activity detected")

            elif feature == "usb_executable_run":
                score += 40
                reasons.append("Executable launched from USB")

        return score, reasons