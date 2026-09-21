import re
from datetime import datetime
from models.feature_vector import FeatureVector


# Pull a file extension out of a file-event's details (a path, a filename,
# or free text). Returns e.g. "xlsx" or None when there is no filename.
_EXT_RE = re.compile(r"\.([A-Za-z0-9]{1,6})(?=[\s\"'|,;)\]]|$)")


def _extension(details):
    if not details:
        return None
    matches = _EXT_RE.findall(details)
    return matches[-1].lower() if matches else None


class FeatureExtractor:

    def extract(self, events):

        """
        Convert Event objects into ML features.
        """

        if not events:
            return {}

        username = events[0].username

        login_hours = []
        logout_hours = []

        failed_login = 0
        file_access = 0
        process_start = 0

        usb_insert = 0
        usb_executable_run = 0

        internet_download = 0
        suspicious_download = 0
        download_then_execute = 0

        powershell_started = 0
        encoded_command = 0
        execution_policy_bypass = 0

        execution_from_temp = 0
        unsigned_binary = 0
        hidden_process = 0
        double_extension = 0
        office_spawned_shell = 0

        certutil_download = 0
        bitsadmin_download = 0
        rundll32_network = 0
        regsvr32_remote_script = 0
        mshta_remote_script = 0

        privilege_escalation = 0
        sudo_abuse = 0

        nmap_scan = 0
        hydra_bruteforce = 0
        ssh_bruteforce = 0
        reverse_shell = 0

        ransomware_behavior = 0
        sensitive_file_access = 0

        persistence_created = 0
        osascript_shell = 0

        network_alert = 0
        port_scan = 0
        malicious_ip_contact = 0
        data_exfiltration = 0
        dns_tunneling = 0
        c2_beaconing = 0

        siem_alert = 0

        # Behavioral statistics accumulators
        all_hours = []
        ip_set = set()
        usb_remove = 0
        weekend_activity = 0
        process_names = set()

        # Live-collectable additions
        off_hours_logon = 0
        file_extensions = set()
        removable_file_events = 0

        for event in events:

            event_time = datetime.fromisoformat(event.timestamp)

            all_hours.append(event_time.hour)

            if event_time.weekday() >= 5:      # Saturday / Sunday
                weekend_activity += 1

            if event.ip and event.ip not in ("-", ""):
                ip_set.add(event.ip)

            if event.event_type == "USB_REMOVE":
                usb_remove += 1

            # Anything originating from removable media: a USB-run
            # executable, or any event whose source/details mark it as
            # coming from a removable drive (live: USB drive-letter
            # tracking; CERT: the to_removable_media flag).
            if event.event_type == "USB_EXECUTABLE_RUN" or \
                    "removable" in (event.details or "").lower():
                removable_file_events += 1

            if event.event_type == "PROCESS_START":
                image = (event.details or "").split("|", 1)[0].strip()
                name = image.replace("\\", "/").rsplit("/", 1)[-1].lower()
                if name:
                    process_names.add(name)

            if event.event_type == "LOGIN_SUCCESS":
                login_hours.append(event_time.hour)
                if event_time.hour < 8 or event_time.hour >= 18:
                    off_hours_logon += 1

            elif event.event_type == "LOGIN_FAILED":
                failed_login += 1

            elif event.event_type == "FILE_ACCESS":
                file_access += 1
                ext = _extension(event.details)
                if ext:
                    file_extensions.add(ext)

            elif event.event_type == "PROCESS_START":
                process_start += 1

            elif event.event_type == "USB_INSERT":
                usb_insert += 1

            elif event.event_type == "USB_EXECUTABLE_RUN":
                usb_executable_run += 1

            elif event.event_type == "INTERNET_DOWNLOAD":
                internet_download += 1

            elif event.event_type == "SUSPICIOUS_DOWNLOAD":
                suspicious_download += 1

            elif event.event_type == "DOWNLOAD_EXECUTE":
                download_then_execute += 1

            elif event.event_type == "POWERSHELL_START":
                powershell_started += 1

            elif event.event_type == "ENCODED_COMMAND":
                encoded_command += 1

            elif event.event_type == "EXECUTION_POLICY_BYPASS":
                execution_policy_bypass += 1

            elif event.event_type == "EXECUTION_FROM_TEMP":
                execution_from_temp += 1

            elif event.event_type == "UNSIGNED_BINARY":
                unsigned_binary += 1

            elif event.event_type == "HIDDEN_PROCESS":
                hidden_process += 1

            elif event.event_type == "DOUBLE_EXTENSION":
                double_extension += 1

            elif event.event_type == "OFFICE_SPAWNED_SHELL":
                office_spawned_shell += 1

            elif event.event_type == "CERTUTIL_DOWNLOAD":
                certutil_download += 1

            elif event.event_type == "BITSADMIN_DOWNLOAD":
                bitsadmin_download += 1

            elif event.event_type == "RUNDLL32_NETWORK":
                rundll32_network += 1

            elif event.event_type == "REGSVR32_REMOTE_SCRIPT":
                regsvr32_remote_script += 1

            elif event.event_type == "MSHTA_REMOTE_SCRIPT":
                mshta_remote_script += 1

            elif event.event_type == "PRIVILEGE_ESCALATION":
                privilege_escalation += 1

            elif event.event_type == "SUDO_ABUSE":
                sudo_abuse += 1

            elif event.event_type == "NMAP_SCAN":
                nmap_scan += 1

            elif event.event_type == "HYDRA_BRUTEFORCE":
                hydra_bruteforce += 1

            elif event.event_type == "SSH_BRUTEFORCE":
                ssh_bruteforce += 1

            elif event.event_type == "REVERSE_SHELL":
                reverse_shell += 1

            elif event.event_type == "RANSOMWARE_BEHAVIOR":
                ransomware_behavior += 1

            elif event.event_type == "SENSITIVE_FILE_ACCESS":
                sensitive_file_access += 1

            elif event.event_type == "PERSISTENCE_CREATED":
                persistence_created += 1

            elif event.event_type == "OSASCRIPT_SHELL":
                osascript_shell += 1

            elif event.event_type == "NETWORK_ALERT":
                network_alert += 1

            elif event.event_type == "PORT_SCAN":
                port_scan += 1

            elif event.event_type == "MALICIOUS_IP_CONTACT":
                malicious_ip_contact += 1

            elif event.event_type == "DATA_EXFILTRATION":
                data_exfiltration += 1

            elif event.event_type == "DNS_TUNNELING":
                dns_tunneling += 1

            elif event.event_type == "C2_BEACONING":
                c2_beaconing += 1

            elif event.event_type == "SIEM_ALERT":
                siem_alert += 1

            elif event.event_type == "LOGOUT":
                logout_hours.append(event_time.hour)

        login_hour = (
            sum(login_hours) / len(login_hours)
            if login_hours else 0
        )

        logout_hour = (
            sum(logout_hours) / len(logout_hours)
            if logout_hours else 0
        )

        # ---- behavioral statistics --------------------------------
        login_count = len(login_hours)
        logout_count = len(logout_hours)
        total_events = len(events)
        night_activity = sum(1 for h in all_hours if 0 <= h <= 5)
        off_hours_activity = sum(1 for h in all_hours if h < 8 or h >= 18)
        active_hours = len(set(all_hours))
        session_span = (max(all_hours) - min(all_hours)) if all_hours else 0
        distinct_ips = len(ip_set)

        # ---- distinct behavioral dimensions -----------------------
        distinct_processes = len(process_names)
        login_attempts = login_count + failed_login
        usb_events = usb_insert + usb_remove
        off_hours_ratio = round(off_hours_activity / total_events, 3) \
            if total_events else 0.0
        event_rate = round(total_events / active_hours, 2) \
            if active_hours else float(total_events)
        file_to_process_ratio = round(file_access / process_start, 2) \
            if process_start else float(file_access)
        distinct_file_types = len(file_extensions)

        features = {
            "username": username,
            "login_hour": login_hour,
            "logout_hour": logout_hour,
            "failed_login": failed_login,
            "process_start": process_start,
            "file_access": file_access,
            "usb_insert": usb_insert,
            "usb_executable_run": usb_executable_run,
            "internet_download": internet_download,
            "suspicious_download": suspicious_download,
            "download_then_execute": download_then_execute,
            "powershell_started": powershell_started,
            "encoded_command": encoded_command,
            "execution_policy_bypass": execution_policy_bypass,
            "execution_from_temp": execution_from_temp,
            "unsigned_binary": unsigned_binary,
            "hidden_process": hidden_process,
            "double_extension": double_extension,
            "office_spawned_shell": office_spawned_shell,
            "certutil_download": certutil_download,
            "bitsadmin_download": bitsadmin_download,
            "rundll32_network": rundll32_network,
            "regsvr32_remote_script": regsvr32_remote_script,
            "mshta_remote_script": mshta_remote_script,
            "privilege_escalation": privilege_escalation,
            "sudo_abuse": sudo_abuse,
            "nmap_scan": nmap_scan,
            "hydra_bruteforce": hydra_bruteforce,
            "ssh_bruteforce": ssh_bruteforce,
            "reverse_shell": reverse_shell,
            "ransomware_behavior": ransomware_behavior,
            "sensitive_file_access": sensitive_file_access,
            "persistence_created": persistence_created,
            "osascript_shell": osascript_shell,
            "network_alert": network_alert,
            "port_scan": port_scan,
            "malicious_ip_contact": malicious_ip_contact,
            "data_exfiltration": data_exfiltration,
            "dns_tunneling": dns_tunneling,
            "c2_beaconing": c2_beaconing,
            "siem_alert": siem_alert,
            "login_count": login_count,
            "logout_count": logout_count,
            "total_events": total_events,
            "night_activity": night_activity,
            "off_hours_activity": off_hours_activity,
            "active_hours": active_hours,
            "session_span": session_span,
            "distinct_ips": distinct_ips,
            "usb_remove": usb_remove,
            "weekend_activity": weekend_activity,
            "off_hours_ratio": off_hours_ratio,
            "event_rate": event_rate,
            "distinct_processes": distinct_processes,
            "file_to_process_ratio": file_to_process_ratio,
            "login_attempts": login_attempts,
            "usb_events": usb_events,
            "off_hours_logon": off_hours_logon,
            "distinct_file_types": distinct_file_types,
            "removable_file_events": removable_file_events,
        }

        return FeatureVector(
            username=features["username"],

            # Authentication
            login_hour=features["login_hour"],
            logout_hour=features["logout_hour"],
            failed_login=features["failed_login"],

            # Process Activity
            process_start=features["process_start"],

            # File Activity
            file_access=features["file_access"],

            # Device Activity
            usb_insert=features["usb_insert"],
            usb_executable_run=features["usb_executable_run"],

            # Download Activity
            internet_download=features["internet_download"],
            suspicious_download=features["suspicious_download"],
            download_then_execute=features["download_then_execute"],

            # PowerShell / Script
            powershell_started=features["powershell_started"],
            encoded_command=features["encoded_command"],
            execution_policy_bypass=features["execution_policy_bypass"],

            # Suspicious Execution
            execution_from_temp=features["execution_from_temp"],
            unsigned_binary=features["unsigned_binary"],
            hidden_process=features["hidden_process"],
            double_extension=features["double_extension"],
            office_spawned_shell=features["office_spawned_shell"],

            # LOLBins
            certutil_download=features["certutil_download"],
            bitsadmin_download=features["bitsadmin_download"],
            rundll32_network=features["rundll32_network"],
            regsvr32_remote_script=features["regsvr32_remote_script"],
            mshta_remote_script=features["mshta_remote_script"],

            # Privilege Escalation
            privilege_escalation=features["privilege_escalation"],
            sudo_abuse=features["sudo_abuse"],

            # Reconnaissance
            nmap_scan=features["nmap_scan"],
            hydra_bruteforce=features["hydra_bruteforce"],
            ssh_bruteforce=features["ssh_bruteforce"],
            reverse_shell=features["reverse_shell"],

            # Impact / Credential Access
            ransomware_behavior=features["ransomware_behavior"],
            sensitive_file_access=features["sensitive_file_access"],

            # Persistence
            persistence_created=features["persistence_created"],
            osascript_shell=features["osascript_shell"],

            # Network Plane (Suricata)
            network_alert=features["network_alert"],
            port_scan=features["port_scan"],
            malicious_ip_contact=features["malicious_ip_contact"],
            data_exfiltration=features["data_exfiltration"],
            dns_tunneling=features["dns_tunneling"],
            c2_beaconing=features["c2_beaconing"],

            # SIEM Plane (Wazuh)
            siem_alert=features["siem_alert"],

            # Behavioral statistics
            login_count=features["login_count"],
            logout_count=features["logout_count"],
            total_events=features["total_events"],
            night_activity=features["night_activity"],
            off_hours_activity=features["off_hours_activity"],
            active_hours=features["active_hours"],
            session_span=features["session_span"],
            distinct_ips=features["distinct_ips"],
            usb_remove=features["usb_remove"],
            weekend_activity=features["weekend_activity"],
            off_hours_ratio=features["off_hours_ratio"],
            event_rate=features["event_rate"],
            distinct_processes=features["distinct_processes"],
            file_to_process_ratio=features["file_to_process_ratio"],
            login_attempts=features["login_attempts"],
            usb_events=features["usb_events"],
            off_hours_logon=features["off_hours_logon"],
            distinct_file_types=features["distinct_file_types"],
            removable_file_events=features["removable_file_events"],
        )