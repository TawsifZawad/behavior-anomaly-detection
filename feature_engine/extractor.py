from collections import Counter
from datetime import datetime


class FeatureExtractor:

    def extract(self, events):

        """
        Convert Event objects into
        ML features.
        """

        features = {}

        if not events:
            return features

        username = events[0].username

        features["username"] = username

        login_hours = []

        failed_login = 0

        file_access = 0

        process_start = 0

        usb_insert = 0

        logout_hours = []

        for event in events:

            event_time = datetime.fromisoformat(event.timestamp)

            if event.event_type == "LOGIN_SUCCESS":
                login_hours.append(event_time.hour)

            elif event.event_type == "LOGIN_FAILED":
                failed_login += 1

            elif event.event_type == "FILE_ACCESS":
                file_access += 1

            elif event.event_type == "PROCESS_START":
                process_start += 1

            elif event.event_type == "USB_INSERT":
                usb_insert += 1

            elif event.event_type == "LOGOUT":
                logout_hours.append(event_time.hour)

        features["login_hour"] = (
            sum(login_hours) / len(login_hours)
            if login_hours else None
        )

        features["logout_hour"] = (
            sum(logout_hours) / len(logout_hours)
            if logout_hours else None
        )

        features["failed_login"] = failed_login

        features["file_access"] = file_access

        features["process_start"] = process_start

        features["usb_insert"] = usb_insert

        return features