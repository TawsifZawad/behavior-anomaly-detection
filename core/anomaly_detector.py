import sqlite3
import os
from collections import defaultdict
from datetime import datetime

from core.process_detector import ProcessDetector
from core.rules import powershell_rule

DB_NAME = "database/behavior.db"


class AnomalyDetector:

    def __init__(self):

        self.connection = sqlite3.connect(DB_NAME)
        self.cursor = self.connection.cursor()
        self.process_detector = ProcessDetector()

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

                process = os.path.basename(
                    details.split("|")[0].strip()
                )

                baseline[username]["processes"].add(process)

            elif event_type == "FILE_ACCESS":

                filename = os.path.basename(
                    details.split("|")[0].strip()
                )

                baseline[username]["files"].add(filename)

        return baseline

    def detect_login_anomalies(self, event, baseline):

        username, _, timestamp, _ = event

        hour = self.parse_hour(timestamp)

        if hour is None:
            return

        if hour not in baseline[username]["hours"]:

            print("[ANOMALY] Unusual Login Time")
            print("User :", username)
            print("Hour :", hour)
            print()

    def detect_process_anomalies(self, event, baseline):

        username, _, _, details = event

        parts = details.split("|", 1)

        process = parts[0].strip()

        command = ""

        if len(parts) > 1:
            command = parts[1].strip()

        process_name = os.path.basename(process)

        if process_name not in baseline[username]["processes"]:

            print("[ANOMALY] Unknown Process")
            print("User    :", username)
            print("Process :", process_name)
            print()

        result = self.process_detector.analyze(
            process,
            command
        )

        if result:

            print("=" * 70)

            print("SUSPICIOUS PROCESS DETECTED")

            print("=" * 70)

            print()

            print("User      :", username)

            print("Process   :", process_name)

            print("Severity  :", result["severity"])

            print("Risk Score:", result["score"])

            print()

            print("Matched Rules")

            print("-" * 30)

            for rule in result["rules"]:

                print(rule)

            print()

            print("MITRE ATT&CK")

            print("-" * 30)

            for attack in result["mitre"]:

                print(
                    attack["id"],
                    "-",
                    attack["name"]
                )

            print()

            print("Command")

            print("-" * 30)

            print(result["command"])

            print()

    def detect_file_anomalies(self, event, baseline):

        username, _, _, details = event

        filename = os.path.basename(
            details.split("|")[0].strip()
        )

        if filename not in baseline[username]["files"]:

            print("[ANOMALY] Unknown File")
            print("User :", username)
            print("File :", filename)
            print()

    def detect(self):

        events = self.load_events()

        baseline = self.build_baseline(events)

        print("=" * 70)
        print("BASELINE BUILT")
        print("=" * 70)

        ignored_users = {
            "-",
            "SYSTEM",
            "LOCAL SERVICE",
            "NETWORK SERVICE"
        }

        for event in events:

            username, event_type, timestamp, details = event

            if not username:
                continue

            if username.endswith("$"):
                continue

            if username.upper() in ignored_users:
                continue

            if event_type in ("LOGIN", "LOGIN_SUCCESS"):

                self.detect_login_anomalies(
                    event,
                    baseline
                )

            elif event_type == "PROCESS_START":

                self.detect_process_anomalies(
                    event,
                    baseline
                )

            elif event_type == "FILE_ACCESS":

                self.detect_file_anomalies(
                    event,
                    baseline
                )

        print()
        print("Detection Finished.")


if __name__ == "__main__":

    detector = AnomalyDetector()

    detector.detect()