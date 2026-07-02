class BehaviorComparator:

    THRESHOLDS = {
        "login_hour": 1,
        "logout_hour": 1,

        "failed_login": 0,

        "process_start": 1,

        "usb_insert": 0,
        "usb_executable_run": 0,

        "file_access": 1
    }

    def compare(self, current, baseline):

        """
        Compare current behavior with stored baseline.
        """

        result = {}

        mapping = {
            "login_hour": 1,
            "logout_hour": 2,
            "failed_login": 3,
            "process_start": 4,
            "usb_insert": 5,
            "usb_executable_run": 6,
            "file_access": 7
        }

        for feature, index in mapping.items():

            current_value = getattr(current, feature)

            baseline_value = baseline[index]

            difference = current_value - baseline_value

            threshold = self.THRESHOLDS.get(feature, 0)

            status = "normal"

            if abs(difference) > threshold:
                status = "changed"

            result[feature] = {
                "baseline": baseline_value,
                "current": current_value,
                "difference": difference,
                "status": status
            }

        return result