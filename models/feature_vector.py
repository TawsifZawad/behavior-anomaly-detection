class FeatureVector:

    def __init__(
        self,
        username,

        login_hour,
        logout_hour,

        failed_login,

        process_start,
        file_access,

        usb_insert,
        usb_executable_run,

        internet_download,
        downloaded_executable_run,

        powershell,
        encoded_powershell,

        certutil,
        bitsadmin,
        rundll32,
        regsvr32,
        mshta,

        privilege_escalation,

        sudo,
        sudo_su,
        chmod_exec,

        curl,
        wget,
        curl_bash,

        netcat,
        nmap,
        hydra,

        ssh_bruteforce,

        osascript,
        launchctl,
        bash_shell,
        zsh_shell
    ):

        self.username = username

        self.login_hour = login_hour
        self.logout_hour = logout_hour

        self.failed_login = failed_login

        self.process_start = process_start
        self.file_access = file_access

        self.usb_insert = usb_insert
        self.usb_executable_run = usb_executable_run

        self.internet_download = internet_download
        self.downloaded_executable_run = downloaded_executable_run

        self.powershell = powershell
        self.encoded_powershell = encoded_powershell

        self.certutil = certutil
        self.bitsadmin = bitsadmin
        self.rundll32 = rundll32
        self.regsvr32 = regsvr32
        self.mshta = mshta

        self.privilege_escalation = privilege_escalation

        self.sudo = sudo
        self.sudo_su = sudo_su
        self.chmod_exec = chmod_exec

        self.curl = curl
        self.wget = wget
        self.curl_bash = curl_bash

        self.netcat = netcat
        self.nmap = nmap
        self.hydra = hydra

        self.ssh_bruteforce = ssh_bruteforce

        self.osascript = osascript
        self.launchctl = launchctl
        self.bash_shell = bash_shell
        self.zsh_shell = zsh_shell

    def to_dict(self):
        return self.__dict__

    def __str__(self):
        return str(self.to_dict())