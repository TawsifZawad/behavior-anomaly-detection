class CorrelationEngine:
    """
    Detect multi-stage attack chains by correlating several suspicious
    behaviors from a single session's feature vector.

    Each correlation carries:
        name         — human readable chain name
        severity     — CRITICAL / HIGH / MEDIUM
        attack_class — U2R / R2L / EXECUTION / PERSISTENCE / DEVICE
        mitre        — list of MITRE technique ids
        description  — explanation for the analyst
    """

    def analyze(self, comparison, features):

        correlations = []

        # =====================================================
        # Device: USB malware
        # =====================================================
        if features.usb_insert > 0 and features.usb_executable_run > 0:
            correlations.append({
                "name": "USB Malware Activity",
                "severity": "CRITICAL",
                "attack_class": "EXECUTION",
                "mitre": ["T1091"],
                "description":
                    "USB device inserted and an executable was launched "
                    "from it.",
            })

        # =====================================================
        # Device: masquerading executable from USB
        # =====================================================
        if features.usb_executable_run > 0 and (
            features.double_extension > 0
            or features.unsigned_binary > 0
        ):
            correlations.append({
                "name": "USB Masquerading Executable",
                "severity": "CRITICAL",
                "attack_class": "EXECUTION",
                "mitre": ["T1091", "T1036.007"],
                "description":
                    "An executable with a masquerading name or an "
                    "invalid signature was launched from removable "
                    "media.",
            })

        # =====================================================
        # Execution: phishing macro chain (office parent)
        # =====================================================
        if features.office_spawned_shell > 0 and (
            features.powershell_started > 0
            or features.encoded_command > 0
            or features.internet_download > 0
        ):
            correlations.append({
                "name": "Office Macro Attack Chain",
                "severity": "CRITICAL",
                "attack_class": "EXECUTION",
                "mitre": ["T1566.001", "T1204.002", "T1059.001"],
                "description":
                    "A document application spawned a script "
                    "interpreter that showed further malicious "
                    "behavior — classic phishing macro execution.",
            })

        # =====================================================
        # R2L: brute force followed by successful login
        # =====================================================
        if features.failed_login >= 3 and features.login_hour is not None:
            correlations.append({
                "name": "Brute Force Then Login (R2L)",
                "severity": "CRITICAL",
                "attack_class": "R2L",
                "mitre": ["T1110"],
                "description":
                    "Multiple failed logins followed by a successful "
                    "session — remote-to-local access pattern.",
            })

        # =====================================================
        # R2L: recon followed by brute force
        # =====================================================
        if features.nmap_scan > 0 and (
            features.hydra_bruteforce > 0 or features.ssh_bruteforce > 0
        ):
            correlations.append({
                "name": "Scan Then Brute Force (R2L)",
                "severity": "CRITICAL",
                "attack_class": "R2L",
                "mitre": ["T1046", "T1110"],
                "description":
                    "Network scanning followed by credential brute "
                    "forcing.",
            })

        # =====================================================
        # U2R: privilege escalation after login
        # =====================================================
        if features.login_hour is not None and (
            features.privilege_escalation > 0 or features.sudo_abuse > 0
        ):
            correlations.append({
                "name": "Privilege Escalation After Login (U2R)",
                "severity": "CRITICAL",
                "attack_class": "U2R",
                "mitre": ["T1548"],
                "description":
                    "A logged-in user attempted to escalate privileges "
                    "— user-to-root pattern.",
            })

        # =====================================================
        # Execution: PowerShell download-and-run chain
        # =====================================================
        if features.powershell_started > 0 and (
            features.encoded_command > 0
            or features.execution_policy_bypass > 0
        ) and features.internet_download > 0:
            correlations.append({
                "name": "Malicious PowerShell Download Chain",
                "severity": "CRITICAL",
                "attack_class": "EXECUTION",
                "mitre": ["T1059.001", "T1105", "T1027"],
                "description":
                    "PowerShell used with obfuscation / policy bypass to "
                    "download and run remote code.",
            })

        # =====================================================
        # Execution: download then execute / execute from temp
        # =====================================================
        if (
            features.internet_download > 0
            or features.suspicious_download > 0
        ) and (
            features.download_then_execute > 0
            or features.execution_from_temp > 0
        ):
            correlations.append({
                "name": "Download and Execute",
                "severity": "HIGH",
                "attack_class": "EXECUTION",
                "mitre": ["T1105"],
                "description":
                    "A downloaded / dropped file was executed, possibly "
                    "from a temporary directory.",
            })

        # =====================================================
        # Execution: payload dropped to disk then launched from the
        # same drop location (file-creation telemetry + execution).
        # =====================================================
        if features.suspicious_download > 0 and (
            features.execution_from_temp > 0
            or features.usb_executable_run > 0
            or features.double_extension > 0
        ):
            correlations.append({
                "name": "Dropped Payload Executed",
                "severity": "CRITICAL",
                "attack_class": "EXECUTION",
                "mitre": ["T1105", "T1204.002"],
                "description":
                    "An executable / script dropped into a download, "
                    "temp or removable location was then launched from "
                    "there.",
            })

        # =====================================================
        # Execution: LOLBin abuse
        # =====================================================
        lolbin_hits = (
            features.certutil_download
            + features.bitsadmin_download
            + features.rundll32_network
            + features.regsvr32_remote_script
            + features.mshta_remote_script
        )
        if lolbin_hits > 0:
            correlations.append({
                "name": "LOLBin Abuse",
                "severity": "HIGH",
                "attack_class": "EXECUTION",
                "mitre": ["T1218", "T1197", "T1105"],
                "description":
                    "A trusted system binary (certutil / bitsadmin / "
                    "rundll32 / regsvr32 / mshta) was used to download or "
                    "proxy-execute code.",
            })

        # =====================================================
        # Impact: ransomware / recovery inhibition
        # =====================================================
        if features.ransomware_behavior > 0:

            # Destroying shadow copies / backups is the pre-encryption
            # step of virtually every ransomware family and has almost
            # no legitimate interactive use.
            mass_file_activity = (
                comparison.get("file_access", {}).get("status") == "changed"
            )

            correlations.append({
                "name": (
                    "Ransomware Impact Chain"
                    if mass_file_activity
                    else "Recovery Inhibition (Pre-Ransomware)"
                ),
                "severity": "CRITICAL",
                "attack_class": "IMPACT",
                "mitre": (
                    ["T1490", "T1486"] if mass_file_activity else ["T1490"]
                ),
                "description":
                    "Backups / shadow copies were destroyed"
                    + (
                        " alongside unusually heavy file activity — "
                        "consistent with active ransomware encryption."
                        if mass_file_activity
                        else " — recovery is being inhibited, the "
                             "standard precursor to ransomware encryption."
                    ),
            })

        # =====================================================
        # Credential Access: secret store dumping. Escalated to
        # CRITICAL when the session also shows escalation or a remote
        # command channel; HIGH on its own.
        # =====================================================
        if features.sensitive_file_access > 0:
            correlations.append({
                "name": "Credential / Secret Store Access",
                "severity": "CRITICAL"
                if (
                    features.privilege_escalation > 0
                    or features.sudo_abuse > 0
                    or features.reverse_shell > 0
                )
                else "HIGH",
                "attack_class": "CREDENTIAL_ACCESS",
                "mitre": ["T1003", "T1552", "T1555"],
                "description":
                    "A credential store or secret file (SAM, LSASS, "
                    "/etc/shadow, SSH keys, browser or password-manager "
                    "vault) was accessed.",
            })

        # =====================================================
        # Execution: reverse shell opened in a session that also
        # delivered a payload — post-exploitation command channel.
        # =====================================================
        if features.reverse_shell > 0 and (
            features.internet_download > 0
            or features.download_then_execute > 0
            or features.usb_executable_run > 0
            or features.encoded_command > 0
        ):
            correlations.append({
                "name": "Reverse Shell After Delivery",
                "severity": "CRITICAL",
                "attack_class": "EXECUTION",
                "mitre": ["T1059", "T1105"],
                "description":
                    "A reverse shell / remote command channel was "
                    "opened in a session that also delivered a payload.",
            })

        # =====================================================
        # Persistence combined with execution / download
        # =====================================================
        if features.persistence_created > 0 and (
            features.internet_download > 0
            or features.download_then_execute > 0
            or features.encoded_command > 0
            or lolbin_hits > 0
        ):
            correlations.append({
                "name": "Persistence With Payload",
                "severity": "CRITICAL",
                "attack_class": "PERSISTENCE",
                "mitre": ["T1547", "T1053"],
                "description":
                    "A persistence mechanism was created alongside "
                    "payload download / execution.",
            })

        # =====================================================
        # CROSS-PLANE correlation (host + network).
        #
        # The unique contribution: a host-plane behavior confirmed by an
        # independent network-plane observation (Suricata) is far higher
        # confidence than either signal alone. These chains only fire
        # when BOTH planes agree.
        # =====================================================

        # Reverse shell / encoded PowerShell (host) confirmed by contact
        # with a malicious / C2 host on the wire.
        if features.malicious_ip_contact > 0 and (
            features.reverse_shell > 0
            or features.encoded_command > 0
            or features.powershell_started > 0
        ):
            correlations.append({
                "name": "Confirmed C2 Channel (Host + Network)",
                "severity": "CRITICAL",
                "attack_class": "COMMAND_AND_CONTROL",
                "mitre": ["T1071", "T1059"],
                "description":
                    "A host executed a remote-command / obfuscated "
                    "payload AND Suricata observed contact with a "
                    "malicious or C2 host — two independent planes agree.",
            })

        # Network scan (wire) + host-side brute force / failed logins:
        # a complete R2L picture confirmed from both sides.
        if features.port_scan > 0 and (
            features.ssh_bruteforce > 0
            or features.hydra_bruteforce > 0
            or features.failed_login >= 3
        ):
            correlations.append({
                "name": "Scan + Brute Force (Host + Network R2L)",
                "severity": "CRITICAL",
                "attack_class": "R2L",
                "mitre": ["T1046", "T1110"],
                "description":
                    "Suricata detected a network scan and the host saw "
                    "brute-force / repeated failed logins from the same "
                    "campaign — cross-plane confirmed R2L.",
            })

        # Credential theft (host) followed by a large outbound transfer
        # (network): the classic access-then-exfiltrate sequence.
        if features.data_exfiltration > 0 and (
            features.sensitive_file_access > 0
            or features.privilege_escalation > 0
            or features.sudo_abuse > 0
        ):
            correlations.append({
                "name": "Exfiltration After Access (Host + Network)",
                "severity": "CRITICAL",
                "attack_class": "EXFILTRATION",
                "mitre": ["T1041", "T1003"],
                "description":
                    "Sensitive data / credentials were accessed on the "
                    "host and a large outbound transfer left the network "
                    "— access-then-exfiltrate confirmed across planes.",
            })

        # SIEM verdict (Wazuh) agreeing with an independent behavioral /
        # network threat our own engine found — the core hybrid claim:
        # rule-based SIEM + anomaly/correlation reinforcing each other.
        if features.siem_alert > 0 and (
            features.malicious_ip_contact > 0
            or features.data_exfiltration > 0
            or features.reverse_shell > 0
            or features.ransomware_behavior > 0
            or features.sensitive_file_access > 0
        ):
            correlations.append({
                "name": "SIEM + Behavioral Confirmation (Hybrid)",
                "severity": "CRITICAL",
                "attack_class": "HYBRID",
                "mitre": ["T1078"],
                "description":
                    "A Wazuh SIEM rule fired in the same session as an "
                    "independent behavioral / network threat detected by "
                    "the anomaly-correlation engine — rule-based and "
                    "anomaly-based detection agree.",
            })

        # Payload delivery (host) whose download source is confirmed
        # malicious on the wire.
        if features.malicious_ip_contact > 0 and (
            features.suspicious_download > 0
            or features.download_then_execute > 0
            or features.internet_download > 0
        ):
            correlations.append({
                "name": "Malicious Download Source (Host + Network)",
                "severity": "CRITICAL",
                "attack_class": "EXECUTION",
                "mitre": ["T1105", "T1071"],
                "description":
                    "A file was downloaded / dropped on the host and "
                    "Suricata flagged the remote source as malicious — "
                    "confirmed malicious delivery.",
            })

        return correlations
