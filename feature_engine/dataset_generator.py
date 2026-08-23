import random
import csv
import os

from models.feature_vector import ML_FEATURES
from config.settings import ML_DATASET_FILE, ML_EVAL_FILE


class DatasetGenerator:
    """
    Cold-start bootstrap dataset.

    Real behavioral data accumulates slowly (one row per session), so
    before enough real history exists the Isolation Forest needs a
    starting point. This generator jitters a user's baseline feature
    vector into synthetic NORMAL samples (label 0 -> training set) and
    fabricates obvious ATTACK samples (label 1 -> evaluation set).

    Once real data crosses MIN_TRAINING_SAMPLES the caller stops relying
    on this generator, and honest evaluation uses EVTX-replayed attacks
    (scripts/replay_attack_samples.py) instead of the synthetic rows.
    """

    HEADER = ["username"] + ML_FEATURES + ["label"]

    # Threat features that a fabricated attack sample turns on.
    THREAT_FEATURES = [
        "suspicious_download",
        "encoded_command",
        "execution_policy_bypass",
        "execution_from_temp",
        "unsigned_binary",
        "hidden_process",
        "double_extension",
        "office_spawned_shell",
        "certutil_download",
        "bitsadmin_download",
        "rundll32_network",
        "regsvr32_remote_script",
        "mshta_remote_script",
        "privilege_escalation",
        "sudo_abuse",
        "nmap_scan",
        "hydra_bruteforce",
        "ssh_bruteforce",
        "reverse_shell",
        "ransomware_behavior",
        "sensitive_file_access",
        "persistence_created",
        "osascript_shell",
        "download_then_execute",
        "network_alert",
        "port_scan",
        "malicious_ip_contact",
        "data_exfiltration",
        "siem_alert",
    ]

    def __init__(self):

        self.normal_rows = []        # label 0 -> training set
        self.eval_normal_rows = []   # label 0 -> held-out eval set
        self.anomaly_rows = []       # label 1 -> eval set

    def _base_values(self, features):
        return {
            feature: getattr(features, feature)
            for feature in ML_FEATURES
        }

    def _jitter_behavioral(self, values):
        """Small variation on the behavioral-statistic features so the
        learned normal has a realistic range rather than a single point."""
        values["total_events"] = max(
            0, int(values.get("total_events", 0) + random.randint(-2, 3))
        )
        values["active_hours"] = max(
            1, int(values.get("active_hours", 1) + random.randint(-1, 2))
        )
        values["session_span"] = max(
            0, round(values.get("session_span", 0) + random.uniform(-1, 1), 2)
        )
        values["off_hours_activity"] = max(
            0, int(values.get("off_hours_activity", 0) + random.randint(0, 2))
        )
        values["night_activity"] = max(
            0, int(values.get("night_activity", 0) + random.randint(0, 1))
        )
        values["distinct_ips"] = max(
            0, int(values.get("distinct_ips", 0) + random.randint(0, 1))
        )
        # distinct behavioral dimensions
        values["distinct_processes"] = max(
            0, int(values.get("distinct_processes", 0) + random.randint(0, 2))
        )
        values["event_rate"] = max(
            0.0, round(values.get("event_rate", 0) + random.uniform(-0.5, 1.0), 2)
        )
        values["off_hours_ratio"] = min(1.0, max(
            0.0, round(values.get("off_hours_ratio", 0)
                       + random.uniform(0, 0.1), 3)
        ))
        values["file_to_process_ratio"] = max(
            0.0, round(values.get("file_to_process_ratio", 0)
                       + random.uniform(-0.3, 0.5), 2)
        )
        values["login_attempts"] = max(
            0, int(values.get("login_attempts", 0) + random.randint(0, 1))
        )
        values["usb_events"] = max(
            0, int(values.get("usb_events", 0) + random.randint(0, 1))
        )
        values["weekend_activity"] = max(
            0, int(values.get("weekend_activity", 0) + random.randint(0, 1))
        )
        values["off_hours_logon"] = max(
            0, int(values.get("off_hours_logon", 0) + random.randint(0, 1))
        )
        values["distinct_file_types"] = max(
            0, int(values.get("distinct_file_types", 0) + random.randint(-1, 1))
        )
        # removable-media activity is rare for normal users -> stays low
        values["removable_file_events"] = max(
            0, int(values.get("removable_file_events", 0))
        )
        return values

    def generate(self, features, samples=200):

        # ------------------------------------------------------------
        # Normal samples: jitter the baseline slightly.
        # ------------------------------------------------------------
        for _ in range(samples):

            values = self._base_values(features)

            values["login_hour"] = round(
                values["login_hour"] + random.uniform(-0.5, 0.5), 2
            )
            values["logout_hour"] = round(
                values["logout_hour"] + random.uniform(-0.5, 0.5), 2
            )
            values["failed_login"] = max(
                0, values["failed_login"] + random.randint(-1, 1)
            )
            values["process_start"] = max(
                0, values["process_start"] + random.randint(-1, 1)
            )
            values["file_access"] = max(
                0, values["file_access"] + random.randint(-1, 2)
            )
            values["usb_insert"] = max(
                0, values["usb_insert"] + random.randint(0, 1)
            )

            self._jitter_behavioral(values)

            self.normal_rows.append(
                self._row(features.username, values, label=0)
            )

        # ------------------------------------------------------------
        # Held-out normal samples for the eval set (so evaluation has
        # both classes and metrics are meaningful).
        # ------------------------------------------------------------
        for _ in range(max(1, samples // 4)):

            values = self._base_values(features)

            values["login_hour"] = round(
                values["login_hour"] + random.uniform(-0.5, 0.5), 2
            )
            values["logout_hour"] = round(
                values["logout_hour"] + random.uniform(-0.5, 0.5), 2
            )
            values["file_access"] = max(
                0, values["file_access"] + random.randint(-1, 2)
            )

            self._jitter_behavioral(values)

            self.eval_normal_rows.append(
                self._row(features.username, values, label=0)
            )

        # ------------------------------------------------------------
        # Attack samples: off-hours, failed logins, threat features on.
        # ------------------------------------------------------------
        for _ in range(samples // 2):

            values = {feature: 0 for feature in ML_FEATURES}

            values["login_hour"] = random.randint(0, 4)
            values["logout_hour"] = random.randint(0, 5)
            values["failed_login"] = random.randint(4, 8)
            values["process_start"] = random.randint(15, 60)
            values["file_access"] = random.randint(30, 300)
            values["usb_insert"] = 1
            values["usb_executable_run"] = 1
            values["internet_download"] = random.randint(1, 20)
            values["powershell_started"] = 1

            # Behavioral statistics — anomalous (off-hours burst, several
            # source IPs, device churn) so attacks are behaviorally
            # distinct on the model's feature set too.
            values["login_count"] = random.randint(1, 3)
            values["logout_count"] = random.randint(0, 2)
            values["total_events"] = (
                values["process_start"] + values["file_access"]
                + random.randint(5, 30)
            )
            values["night_activity"] = random.randint(5, 40)
            values["off_hours_activity"] = random.randint(10, 60)
            values["active_hours"] = random.randint(1, 4)
            values["session_span"] = random.randint(0, 6)
            values["distinct_ips"] = random.randint(1, 4)
            values["usb_remove"] = 1

            # distinct behavioral dimensions — anomalous
            values["weekend_activity"] = random.randint(0, 10)
            values["off_hours_ratio"] = round(random.uniform(0.5, 1.0), 3)
            values["event_rate"] = round(random.uniform(10, 50), 2)
            values["distinct_processes"] = random.randint(10, 40)
            values["file_to_process_ratio"] = round(random.uniform(2, 10), 2)
            values["login_attempts"] = random.randint(5, 12)
            values["usb_events"] = random.randint(1, 2)
            # live-collectable additions — anomalous for attacks
            values["off_hours_logon"] = random.randint(1, 3)
            values["distinct_file_types"] = random.randint(5, 30)
            values["removable_file_events"] = random.randint(1, 3)

            for feature in self.THREAT_FEATURES:
                values[feature] = 1

            self.anomaly_rows.append(
                self._row(features.username, values, label=1)
            )

    def _row(self, username, values, label):
        return (
            [username]
            + [values[feature] for feature in ML_FEATURES]
            + [label]
        )

    def save(
        self,
        dataset_path=ML_DATASET_FILE,
        eval_path=ML_EVAL_FILE
    ):

        # Normal (label 0) -> training set
        self._write(dataset_path, self.normal_rows)

        # Held-out normals + synthetic attacks -> evaluation set
        # (cold-start only; real evaluation uses EVTX-replayed attacks).
        eval_rows = self.eval_normal_rows + self.anomaly_rows
        if eval_rows:
            self._write(eval_path, eval_rows)

        print(
            f"Generated {len(self.normal_rows)} training normals, "
            f"{len(self.eval_normal_rows)} eval normals, "
            f"{len(self.anomaly_rows)} attack samples."
        )
        print(f"Training set : {dataset_path}")
        print(f"Eval set     : {eval_path}")

    def _write(self, file_path, rows):

        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, "w", newline="", encoding="utf-8") as file:

            writer = csv.writer(file)
            writer.writerow(self.HEADER)
            writer.writerows(rows)
