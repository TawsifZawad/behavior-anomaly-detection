class RiskEngine:
    """
    Two-tier behavioral risk scoring.

    Tier 1 (concern) — baseline deviation:
        How different is this session from the user's learned baseline
        (login hour, process/file volume, USB). Low weights: a change of
        routine is worth noticing, not alerting on.

    Tier 2 (threat) — context-aware behaviors:
        Specific dangerous actions detected in the session's feature
        vector (encoded PowerShell, LOLBin downloads, privilege
        escalation, brute force, persistence). High weights: these are
        threats regardless of the user's baseline.

    This encodes the intended policy: "a user running PowerShell is a
    concern; a user running a harmful command is a threat."
    """

    # Tier 1 — deviation from baseline (read from `comparison`)
    DEVIATION_RULES = {
        "login_hour": (20, "Unusual login hour"),
        "logout_hour": (10, "Unusual logout hour"),
        "failed_login": (40, "Failed login attempts"),
        "process_start": (10, "Different process activity"),
        "file_access": (10, "Different file access activity"),
        "usb_insert": (20, "USB activity detected"),
    }

    # Tier 2 — context-aware threat behaviors (read from the FeatureVector).
    # Each entry: feature_name -> (weight, reason)
    CONTEXT_RULES = {
        "usb_executable_run":      (40, "Executable launched from USB / removable media"),
        "powershell_started":      (10, "PowerShell / script interpreter used"),
        "internet_download":       (20, "File downloaded from the internet"),
        "suspicious_download":     (30, "Executable / script dropped in a download or temp location"),
        "download_then_execute":   (40, "Downloaded file was executed"),

        "encoded_command":         (50, "Encoded / obfuscated command executed"),
        "execution_policy_bypass": (30, "PowerShell execution policy bypassed"),
        "hidden_process":          (30, "Process launched in a hidden window"),

        "execution_from_temp":     (30, "Execution from a temp / download directory"),
        "unsigned_binary":         (20, "Unsigned binary executed"),
        "double_extension":        (50, "Executable masquerading with a double extension"),
        "office_spawned_shell":    (60, "Office / document app spawned a shell or script interpreter"),

        "certutil_download":       (40, "certutil used to download a file"),
        "bitsadmin_download":      (40, "bitsadmin used to transfer a file"),
        "rundll32_network":        (40, "rundll32 used for remote execution"),
        "regsvr32_remote_script":  (40, "regsvr32 loaded a remote script"),
        "mshta_remote_script":     (40, "mshta executed a remote script"),

        "privilege_escalation":    (50, "Privilege escalation attempt (U2R)"),
        "sudo_abuse":              (50, "Suspicious sudo / root escalation (U2R)"),

        "nmap_scan":               (30, "Network scanning activity"),
        "hydra_bruteforce":        (50, "Brute-force tool executed (R2L)"),
        "ssh_bruteforce":          (50, "SSH brute-force activity (R2L)"),
        "reverse_shell":           (60, "Reverse shell / remote command channel"),

        "ransomware_behavior":     (70, "Backup / shadow copy destruction (ransomware)"),
        "sensitive_file_access":   (60, "Credential store or secret file accessed"),

        "persistence_created":     (40, "Persistence mechanism created"),
        "osascript_shell":         (40, "AppleScript shell execution"),

        # Network plane (Suricata)
        "network_alert":           (30, "Network IDS signature alert (Suricata)"),
        "port_scan":               (30, "Network scan detected on the wire"),
        "malicious_ip_contact":    (60, "Contact with a malicious / C2 host"),
        "data_exfiltration":       (50, "Large outbound transfer (possible exfiltration)"),
        "c2_beaconing":            (60, "C2 beaconing - periodic callbacks to an external host"),
        "dns_tunneling":           (60, "DNS tunnelling - data/command channel over DNS"),

        # SIEM plane (Wazuh)
        "siem_alert":              (30, "Wazuh SIEM rule alert"),
    }

    def calculate(self, comparison, features=None):
        """
        Calculate risk score from baseline deviation (comparison) and,
        when a FeatureVector is supplied, context-aware threat behaviors.

        `features` is optional so any legacy caller passing only the
        comparison still works (it simply gets Tier-1 scoring only).
        """

        score = 0
        reasons = []

        # ---- Tier 1: baseline deviation ----------------------------
        for feature, value in comparison.items():

            if value["status"] == "normal":
                continue

            if feature not in self.DEVIATION_RULES:
                continue

            risk_score, reason = self.DEVIATION_RULES[feature]

            score += risk_score
            reasons.append(reason)

        # ---- Tier 2: context-aware threats -------------------------
        if features is not None:

            for feature, (risk_score, reason) in self.CONTEXT_RULES.items():

                if getattr(features, feature, 0):

                    score += risk_score
                    reasons.append(reason)

        return score, reasons
