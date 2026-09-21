from dataclasses import dataclass


# Canonical ordered list of the numeric features used by the ML model.
# Single source of truth imported by ml/trainer.py, ml/predictor.py,
# ml/evaluator.py and feature_engine/dataset_builder.py so the column
# order can never drift between training, prediction and evaluation.
ML_FEATURES = [

    "login_hour",
    "logout_hour",
    "failed_login",

    "process_start",
    "file_access",

    "usb_insert",
    "usb_executable_run",

    "internet_download",
    "suspicious_download",
    "download_then_execute",

    "powershell_started",
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

    "network_alert",
    "port_scan",
    "malicious_ip_contact",
    "data_exfiltration",

    "siem_alert",

    # Behavioral statistics (derived from the raw event stream, not
    # rules). Some are intermediate accumulators; the anomaly model uses
    # the distinct subset in ML_MODEL_FEATURES below.
    "login_count",
    "logout_count",
    "total_events",
    "night_activity",
    "off_hours_activity",
    "active_hours",
    "session_span",
    "distinct_ips",
    "usb_remove",

    # Distinct behavioral dimensions used by the anomaly model.
    "weekend_activity",
    "off_hours_ratio",
    "event_rate",
    "distinct_processes",
    "file_to_process_ratio",
    "login_attempts",
    "usb_events",

    # Live-collectable behavioural dimensions (Windows 4624/4663 + USB
    # drive-letter tracking; also derivable from CERT logon/file logs).
    "off_hours_logon",
    "distinct_file_types",
    "removable_file_events",
]


# Features the Isolation Forest actually learns from: raw behavioral,
# temporal and volume signals that describe HOW a user is behaving. The
# remaining ML_FEATURES are rule-derived threat indicators (encoded
# command, LOLBin, USB-exec, network/SIEM alerts, ...) already handled by
# the rule and correlation engines. Feeding the anomaly model only the
# behavioral features makes it a genuine UEBA detector of NOVEL deviations
# (unusual hours / volume / failed logins / device use) instead of a
# re-detector of hits the rules already produced. The full ML_FEATURES
# list remains the dataset/record schema.
ML_MODEL_FEATURES = [
    # Each entry answers a DISTINCT behavioral question about the user
    # (no two are versions of the same signal).

    # --- WHEN do they work? ---
    "login_hour",             # start-of-work time
    "logout_hour",            # end-of-work time
    "session_span",           # how long the session lasts
    "off_hours_ratio",        # fraction of activity outside business hours
    "weekend_activity",       # activity on weekends

    # --- HOW INTENSE / how much? ---
    "event_rate",             # activity intensity (events per active hour)
    "active_hours",           # how spread across the day
    "process_start",          # how many programs launched
    "file_access",            # how much file activity

    # --- WHAT STYLE / how varied? ---
    "distinct_processes",     # variety of distinct programs run
    "file_to_process_ratio",  # file-heavy vs process-heavy work style

    # --- AUTHENTICATION behaviour ---
    "failed_login",           # authentication failures
    "login_attempts",         # how often they authenticate
    "off_hours_logon",        # successful logins outside business hours

    # --- FILE STYLE ---
    "distinct_file_types",    # variety of file extensions touched

    # --- DEVICE & NETWORK behaviour ---
    "usb_events",             # removable-media usage
    "removable_file_events",  # files/executables from removable media
    "distinct_ips",           # number of network source locations
]


# E-mail and web-log behavioural features. These are BENCHMARK-ONLY: CERT
# r4.2 records e-mail (email.csv) and web (http.csv) activity, so the CERT
# training/evaluation scripts can learn from them and measure the benefit.
# They are deliberately NOT part of ML_MODEL_FEATURES, because the live
# host collectors do not yet read e-mail / web activity off a running
# machine — so the deployed model's input dimension is unchanged. When a
# live e-mail/web collector is added, promote the ones it can fill into
# ML_MODEL_FEATURES and retrain. (Future-work item, made concrete on the
# CERT benchmark by scripts/cert_train.py and scripts/cert_eval.py.)
CERT_EXTRA_FEATURES = [
    "web_events",             # volume of web requests
    "distinct_web_domains",   # variety of sites visited
    "email_sent",             # e-mails sent
    "external_email_ratio",   # fraction of sent mail to external domains
    "email_attachments",      # attachments sent (exfil signal)
]


@dataclass
class FeatureVector:

    # ==========================
    # Identity
    # ==========================

    username: str

    # ==========================
    # Authentication
    # ==========================

    login_hour: float | None
    logout_hour: float | None
    failed_login: int

    # ==========================
    # Process Activity
    # ==========================

    process_start: int

    # ==========================
    # File Activity
    # ==========================

    file_access: int

    # ==========================
    # Device Activity
    # ==========================

    usb_insert: int
    usb_executable_run: int

    # ==========================
    # Download Activity
    # ==========================

    internet_download: int
    suspicious_download: int
    download_then_execute: int

    # ==========================
    # PowerShell / Script
    # ==========================

    powershell_started: int
    encoded_command: int
    execution_policy_bypass: int

    # ==========================
    # Suspicious Execution
    # ==========================

    execution_from_temp: int
    unsigned_binary: int
    hidden_process: int
    double_extension: int
    office_spawned_shell: int

    # ==========================
    # LOLBins (Windows)
    # ==========================

    certutil_download: int
    bitsadmin_download: int
    rundll32_network: int
    regsvr32_remote_script: int
    mshta_remote_script: int

    # ==========================
    # Privilege Escalation
    # ==========================

    privilege_escalation: int
    sudo_abuse: int

    # ==========================
    # Reconnaissance
    # ==========================

    nmap_scan: int
    hydra_bruteforce: int
    ssh_bruteforce: int
    reverse_shell: int

    # ==========================
    # Impact / Credential Access
    # ==========================

    ransomware_behavior: int
    sensitive_file_access: int

    # ==========================
    # Persistence
    # ==========================

    persistence_created: int
    osascript_shell: int

    # ==========================
    # Network Plane (Suricata)
    # ==========================

    network_alert: int
    port_scan: int
    malicious_ip_contact: int
    data_exfiltration: int

    # ==========================
    # SIEM Plane (Wazuh)
    # ==========================

    siem_alert: int

    # ==========================
    # Behavioral statistics
    # ==========================

    login_count: int
    logout_count: int
    total_events: int
    night_activity: int
    off_hours_activity: int
    active_hours: int
    session_span: float
    distinct_ips: int
    usb_remove: int

    # Distinct behavioral dimensions (model features)
    weekend_activity: int
    off_hours_ratio: float
    event_rate: float
    distinct_processes: int
    file_to_process_ratio: float
    login_attempts: int
    usb_events: int

    # Live-collectable additions (default 0 so any other construction site
    # keeps working; the extractor always fills them).
    off_hours_logon: int = 0
    distinct_file_types: int = 0
    removable_file_events: int = 0

    # Network-BEHAVIOUR indicators (Suricata behaviour pass, not
    # signatures). Rule/correlation inputs only — deliberately NOT in
    # ML_FEATURES / ML_MODEL_FEATURES, so the anomaly model's input
    # dimension is unchanged. Default 0; the extractor fills them.
    dns_tunneling: int = 0
    c2_beaconing: int = 0