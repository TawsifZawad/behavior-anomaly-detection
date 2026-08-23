class BehaviorComparator:

    # Absolute tolerance per feature.
    THRESHOLDS = {
        "login_hour": 1,
        "logout_hour": 1,

        "failed_login": 0,

        "process_start": 1,

        "usb_insert": 0,
        "usb_executable_run": 0,

        "file_access": 1
    }

    # High-volume features whose "normal" scales with the user's activity
    # (a workstation runs a very different number of processes than the
    # toy sample users). For these the effective tolerance is a fraction
    # of the baseline, with an absolute floor — otherwise every real scan
    # trivially looks "changed".
    RELATIVE = {
        "process_start": 0.5,
        "file_access": 0.5,
    }
    RELATIVE_FLOOR = 5

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

            if feature in self.RELATIVE:
                threshold = max(
                    self.RELATIVE_FLOOR,
                    self.RELATIVE[feature] * abs(baseline_value or 0),
                    threshold,
                )

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