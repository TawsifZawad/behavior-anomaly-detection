import sqlite3
import os
from collections import Counter, defaultdict
from datetime import datetime

DB_NAME = "database/behavior.db"


class BaselineTrainer:

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

        except Exception:
            return None

    def build_profiles(self, events):

        profiles = defaultdict(lambda: {

            "login_hours": [],
            "processes": [],
            "files": [],

            "login_count": 0,
            "process_count": 0,
            "file_count": 0

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

            profile = profiles[username]

            if event_type in ("LOGIN", "LOGIN_SUCCESS"):

                hour = self.parse_hour(timestamp)

                if hour is not None:
                    profile["login_hours"].append(hour)

                profile["login_count"] += 1

            elif event_type == "PROCESS_START":

                process = os.path.basename(details)

                profile["processes"].append(process)

                profile["process_count"] += 1

            elif event_type == "FILE_ACCESS":

                filename = os.path.basename(
                    details.split("|")[0].strip()
                )

                profile["files"].append(filename)

                profile["file_count"] += 1

        return profiles

    def train(self):

        events = self.load_events()

        print(f"\nLoaded {len(events)} events\n")

        profiles = self.build_profiles(events)

        for user, profile in profiles.items():

            print("=" * 60)

            print("User :", user)

            print()

            print("Normal Login Hours")
            print("------------------")
            print(sorted(set(profile["login_hours"])))

            print()

            print("Top Processes")
            print("-------------")

            for process, count in Counter(
                profile["processes"]
            ).most_common(10):

                print(f"{process:<30} {count}")

            print()

            print("Top Files")
            print("---------")

            for file, count in Counter(
                profile["files"]
            ).most_common(10):

                print(f"{file:<30} {count}")

            print()

            print("Statistics")
            print("----------")
            print("Login Events   :", profile["login_count"])
            print("Process Events :", profile["process_count"])
            print("File Events    :", profile["file_count"])

            print()


if __name__ == "__main__":

    trainer = BaselineTrainer()

    trainer.train()