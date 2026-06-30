import random
import csv
import os


class DatasetGenerator:

    def __init__(self):

        self.rows = []

    def generate(self, features, samples=200):

        for _ in range(samples):

            login_hour = round(
                features.login_hour + random.uniform(-0.5, 0.5), 2
            )

            logout_hour = round(
                features.logout_hour + random.uniform(-0.5, 0.5), 2
            )

            failed_login = max(
                0,
                features.failed_login + random.randint(-1, 1)
            )

            process_start = max(
                0,
                features.process_start + random.randint(-1, 1)
            )

            usb_insert = max(
                0,
                features.usb_insert + random.randint(0, 1)
            )

            file_access = max(
                0,
                features.file_access + random.randint(-1, 2)
            )

            self.rows.append([
                features.username,
                login_hour,
                logout_hour,
                failed_login,
                process_start,
                usb_insert,
                file_access,
                0
            ])

    def save(
        self,
        file_path="data/ml_dataset.csv"
    ):

        os.makedirs(
            os.path.dirname(file_path),
            exist_ok=True
        )

        with open(
            file_path,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "username",
                "login_hour",
                "logout_hour",
                "failed_login",
                "process_start",
                "usb_insert",
                "file_access",
                "label"
            ])

            writer.writerows(self.rows)

        print(f"Generated {len(self.rows)} samples.")
        print(f"Saved to {file_path}")