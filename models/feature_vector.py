from dataclasses import dataclass


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

    # ==========================
    # Persistence
    # ==========================

    persistence_created: int
    osascript_shell: int