from datetime import datetime
from models.feature_vector import FeatureVector


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
        download_then_execute = 0

        powershell_started = 0
        encoded_command = 0
        execution_policy_bypass = 0

        execution_from_temp = 0
        unsigned_binary = 0
        hidden_process = 0

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

        persistence_created = 0
        osascript_shell = 0

        for event in events:

            event_time = datetime.fromisoformat(event.timestamp)

            if event.event_type == "LOGIN_SUCCESS":
                login_hours.append(event_time.hour)

            elif event.event_type == "LOGIN_FAILED":
                failed_login += 1

            elif event.event_type == "FILE_ACCESS":
                file_access += 1

            elif event.event_type == "PROCESS_START":
                process_start += 1

            elif event.event_type == "USB_INSERT":
                usb_insert += 1

            elif event.event_type == "USB_EXECUTABLE_RUN":
                usb_executable_run += 1

            elif event.event_type == "INTERNET_DOWNLOAD":
                internet_download += 1

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

            elif event.event_type == "PERSISTENCE_CREATED":
                persistence_created += 1

            elif event.event_type == "OSASCRIPT_SHELL":
                osascript_shell += 1

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
            "download_then_execute": download_then_execute,
            "powershell_started": powershell_started,
            "encoded_command": encoded_command,
            "execution_policy_bypass": execution_policy_bypass,
            "execution_from_temp": execution_from_temp,
            "unsigned_binary": unsigned_binary,
            "hidden_process": hidden_process,
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
            "persistence_created": persistence_created,
            "osascript_shell": osascript_shell
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
            download_then_execute=features["download_then_execute"],

            # PowerShell / Script
            powershell_started=features["powershell_started"],
            encoded_command=features["encoded_command"],
            execution_policy_bypass=features["execution_policy_bypass"],

            # Suspicious Execution
            execution_from_temp=features["execution_from_temp"],
            unsigned_binary=features["unsigned_binary"],
            hidden_process=features["hidden_process"],

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

            # Persistence
            persistence_created=features["persistence_created"],
            osascript_shell=features["osascript_shell"]
        )