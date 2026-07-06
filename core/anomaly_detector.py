import sqlite3
import os
from collections import defaultdict
from datetime import datetime

DB_NAME = "database/behavior.db"


class AnomalyDetector:

    def __init__(self):

        self.connection = sqlite3.connect(DB_NAME)
        self.cursor = self.connection.cursor()

    def load_events(self):

        self.cursor.execute("""
            SELECT
                username,
                event_type,
                timestamp,
                details
            FROM events
            ORDER BY timestamp
        """)

        return self.cursor.fetchall()

    def parse_hour(self, timestamp):

        try:

            timestamp = timestamp.replace("Z", "")

            if "." in timestamp:

                left, right = timestamp.split(".", 1)

                digits = ""

                for c in right:

                    if c.isdigit():
                        digits += c
                    else:
                        break

                digits = digits[:6]

                timestamp = left + "." + digits

            return datetime.fromisoformat(timestamp).hour

        except:
            return None

    def build_baseline(self, events):

        baseline = defaultdict(lambda: {
            "hours": set(),
            "processes": set(),
            "files": set()
        })

        ignored_users = {
            "-",
            "SYSTEM",
            "LOCAL SERVICE",
            "NETWORK SERVICE"
        }

        for username, event_type, timestamp, details in events:

            if not username:
                continue

            if username.endswith("$"):
                continue

            if username.upper() in ignored_users:
                continue

            if event_type in ("LOGIN", "LOGIN_SUCCESS"):

                hour = self.parse_hour(timestamp)

                if hour is not None:
                    baseline[username]["hours"].add(hour)

            elif event_type == "PROCESS_START":

                process = os.path.basename(details)

                baseline[username]["processes"].add(process)

            elif event_type == "FILE_ACCESS":

                filename = os.path.basename(
                    details.split("|")[0].strip()
                )

                baseline[username]["files"].add(filename)

        return baseline

    def detect(self):

        events = self.load_events()

        baseline = self.build_baseline(events)

        print("=" * 70)
        print("BASELINE SUMMARY")
        print("=" * 70)

        for user, profile in baseline.items():

            print()

            print("User :", user)

            print()

            print("Login Hours")
            print(sorted(profile["hours"]))

            print()

            print("Known Processes")

            for process in sorted(profile["processes"]):
                print("  ", process)

            print()

            print("Known Files")

            for file in sorted(profile["files"]):
                print("  ", file)

            print()

            print("-" * 70)


if __name__ == "__main__":

    detector = AnomalyDetector()

    detector.detect()