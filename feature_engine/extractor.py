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
        downloaded_executable_run = 0

        powershell = 0
        encoded_powershell = 0

        certutil = 0
        bitsadmin = 0
        rundll32 = 0
        regsvr32 = 0
        mshta = 0

        privilege_escalation = 0

        sudo = 0
        sudo_su = 0
        chmod_exec = 0

        curl = 0
        wget = 0
        curl_bash = 0

        netcat = 0
        nmap = 0
        hydra = 0

        ssh_bruteforce = 0

        osascript = 0
        launchctl = 0
        bash_shell = 0
        zsh_shell = 0

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

            elif event.event_type == "DOWNLOADED_EXECUTABLE_RUN":
                downloaded_executable_run += 1

            elif event.event_type == "POWERSHELL":
                powershell += 1

            elif event.event_type == "ENCODED_POWERSHELL":
                encoded_powershell += 1

            elif event.event_type == "CERTUTIL":
                certutil += 1

            elif event.event_type == "BITSADMIN":
                bitsadmin += 1

            elif event.event_type == "RUNDLL32":
                rundll32 += 1

            elif event.event_type == "REGSVR32":
                regsvr32 += 1

            elif event.event_type == "MSHTA":
                mshta += 1

            elif event.event_type == "PRIVILEGE_ESCALATION":
                privilege_escalation += 1

            elif event.event_type == "SUDO":
                sudo += 1

            elif event.event_type == "SUDO_SU":
                sudo_su += 1

            elif event.event_type == "CHMOD_EXEC":
                chmod_exec += 1

            elif event.event_type == "CURL":
                curl += 1

            elif event.event_type == "WGET":
                wget += 1

            elif event.event_type == "CURL_BASH":
                curl_bash += 1

            elif event.event_type == "NETCAT":
                netcat += 1

            elif event.event_type == "NMAP":
                nmap += 1

            elif event.event_type == "HYDRA":
                hydra += 1

            elif event.event_type == "SSH_BRUTEFORCE":
                ssh_bruteforce += 1

            elif event.event_type == "OSASCRIPT":
                osascript += 1

            elif event.event_type == "LAUNCHCTL":
                launchctl += 1

            elif event.event_type == "BASH_SHELL":
                bash_shell += 1

            elif event.event_type == "ZSH_SHELL":
                zsh_shell += 1

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

        return FeatureVector(
            username=username,

            login_hour=login_hour,
            logout_hour=logout_hour,

            failed_login=failed_login,

            process_start=process_start,
            file_access=file_access,

            usb_insert=usb_insert,
            usb_executable_run=usb_executable_run,

            internet_download=internet_download,
            downloaded_executable_run=downloaded_executable_run,

            powershell=powershell,
            encoded_powershell=encoded_powershell,

            certutil=certutil,
            bitsadmin=bitsadmin,
            rundll32=rundll32,
            regsvr32=regsvr32,
            mshta=mshta,

            privilege_escalation=privilege_escalation,

            sudo=sudo,
            sudo_su=sudo_su,
            chmod_exec=chmod_exec,

            curl=curl,
            wget=wget,
            curl_bash=curl_bash,

            netcat=netcat,
            nmap=nmap,
            hydra=hydra,

            ssh_bruteforce=ssh_bruteforce,

            osascript=osascript,
            launchctl=launchctl,
            bash_shell=bash_shell,
            zsh_shell=zsh_shell
        )