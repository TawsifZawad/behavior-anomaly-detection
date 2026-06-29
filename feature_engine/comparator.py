class BehaviorComparator:

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
            "file_access": 6
        }

        for feature, index in mapping.items():

            current_value = getattr(current, feature)

            baseline_value = baseline[index]

            difference = current_value - baseline_value

            status = "normal"

            if difference != 0:
                status = "changed"

            result[feature] = {
                "baseline": baseline_value,
                "current": current_value,
                "difference": difference,
                "status": status
            }

        return result