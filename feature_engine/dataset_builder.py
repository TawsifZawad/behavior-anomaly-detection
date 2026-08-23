import csv
import os

from models.feature_vector import ML_FEATURES
from config.settings import ML_DATASET_FILE


class DatasetBuilder:
    """
    Appends real per-session feature vectors to the ML training dataset.
    Every appended row is labelled normal (0): the training set is a
    record of genuine user behavior that Isolation Forest learns from.
    Attack rows (label 1) are written separately to the evaluation set.
    """

    HEADER = ["username"] + ML_FEATURES + ["label"]

    def __init__(self, file_path=ML_DATASET_FILE):

        self.file = file_path

    def initialize(self):

        os.makedirs(os.path.dirname(self.file), exist_ok=True)

        if os.path.exists(self.file):

            # Feature schema changed (ML_FEATURES gained/lost columns):
            # appending to the old file would silently misalign columns,
            # so start the dataset over with the current header.
            with open(self.file, newline="") as csvfile:
                existing_header = next(csv.reader(csvfile), None)

            if existing_header == self.HEADER:
                return

            print(
                "Dataset header out of date "
                f"({self.file}); rebuilding with current features."
            )

        with open(self.file, "w", newline="") as csvfile:

            writer = csv.writer(csvfile)
            writer.writerow(self.HEADER)

    def append(self, features, label=0):

        self.initialize()

        row = [features.username]

        for feature in ML_FEATURES:
            row.append(getattr(features, feature))

        row.append(label)

        with open(self.file, "a", newline="") as csvfile:

            writer = csv.writer(csvfile)
            writer.writerow(row)
