import csv
import os


class DatasetBuilder:

    def __init__(self):

        self.file = "data/ml_dataset.csv"

    def initialize(self):

        if os.path.exists(self.file):
            return

        with open(self.file, "w", newline="") as csvfile:

            writer = csv.writer(csvfile)

            writer.writerow([
                "username",
                "login_hour",
                "logout_hour",
                "failed_login",
                "file_access",
                "process_start",
                "usb_insert"
            ])

    def append(self, features):

        with open(self.file, "a", newline="") as csvfile:

            writer = csv.writer(csvfile)

            writer.writerow([
                features.username,
                features.login_hour,
                features.logout_hour,
                features.failed_login,
                features.file_access,
                features.process_start,
                features.usb_insert
            ])