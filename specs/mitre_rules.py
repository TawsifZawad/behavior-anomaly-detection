# =====================================================================
# MITRE ATT&CK technique mapping
#
# keyword -> {"id": <technique id>, "name": <technique name>}
#
# Keywords mirror those in specs/process_rules.py. The classifier
# (core/process_detector.py) attaches these techniques to a detection
# when the corresponding keyword is matched.
# =====================================================================

MITRE_MAPPING = {

    # -----------------------------------------------------------------
    # PowerShell / script abuse
    # -----------------------------------------------------------------

    "-executionpolicy bypass": {"id": "T1059.001", "name": "PowerShell"},
    "-exec bypass":            {"id": "T1059.001", "name": "PowerShell"},
    "-ep bypass":              {"id": "T1059.001", "name": "PowerShell"},

    "-encodedcommand":  {"id": "T1027", "name": "Obfuscated Files or Information"},
    "-enc ":            {"id": "T1027", "name": "Obfuscated Files or Information"},
    "powershell -e ":     {"id": "T1027", "name": "Obfuscated Files or Information"},
    "powershell.exe -e ": {"id": "T1027", "name": "Obfuscated Files or Information"},
    "pwsh -e ":           {"id": "T1027", "name": "Obfuscated Files or Information"},
    "frombase64string": {"id": "T1027", "name": "Obfuscated Files or Information"},

    "invoke-expression":   {"id": "T1059.001", "name": "PowerShell"},
    "iex ":                {"id": "T1059.001", "name": "PowerShell"},
    "invoke-command":      {"id": "T1059.001", "name": "PowerShell"},
    "reflection.assembly": {"id": "T1620", "name": "Reflective Code Loading"},

    "downloadstring":           {"id": "T1105", "name": "Ingress Tool Transfer"},
    "downloadfile":             {"id": "T1105", "name": "Ingress Tool Transfer"},
    "invoke-webrequest":        {"id": "T1105", "name": "Ingress Tool Transfer"},
    "start-bitstransfer":       {"id": "T1105", "name": "Ingress Tool Transfer"},
    "new-object net.webclient": {"id": "T1105", "name": "Ingress Tool Transfer"},
    "system.net.webclient":     {"id": "T1105", "name": "Ingress Tool Transfer"},
    "curl ":                    {"id": "T1105", "name": "Ingress Tool Transfer"},
    "wget ":                    {"id": "T1105", "name": "Ingress Tool Transfer"},

    "-windowstyle hidden": {"id": "T1564", "name": "Hide Artifacts"},
    "-w hidden":           {"id": "T1564", "name": "Hide Artifacts"},

    "-nop":            {"id": "T1059.001", "name": "PowerShell"},
    "-noprofile":      {"id": "T1059.001", "name": "PowerShell"},
    "-noninteractive": {"id": "T1059.001", "name": "PowerShell"},
    "-noni":           {"id": "T1059.001", "name": "PowerShell"},

    "add-mppreference": {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools"},
    "set-mppreference": {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools"},

    # -----------------------------------------------------------------
    # LOLBins
    # -----------------------------------------------------------------

    "certutil -urlcache":     {"id": "T1105", "name": "Ingress Tool Transfer"},
    "certutil.exe -urlcache": {"id": "T1105", "name": "Ingress Tool Transfer"},
    "certutil -decode":       {"id": "T1140", "name": "Deobfuscate/Decode Files or Information"},
    "-urlcache -split":       {"id": "T1105", "name": "Ingress Tool Transfer"},

    "bitsadmin /transfer":     {"id": "T1197", "name": "BITS Jobs"},
    "bitsadmin.exe /transfer": {"id": "T1197", "name": "BITS Jobs"},

    "rundll32 javascript":     {"id": "T1218.011", "name": "System Binary Proxy Execution: Rundll32"},
    "rundll32.exe javascript": {"id": "T1218.011", "name": "System Binary Proxy Execution: Rundll32"},
    "rundll32 http":           {"id": "T1218.011", "name": "System Binary Proxy Execution: Rundll32"},

    "regsvr32 /i:http": {"id": "T1218.010", "name": "System Binary Proxy Execution: Regsvr32"},
    "regsvr32 /u /i:":  {"id": "T1218.010", "name": "System Binary Proxy Execution: Regsvr32"},
    "scrobj.dll":       {"id": "T1218.010", "name": "System Binary Proxy Execution: Regsvr32"},

    "mshta http":       {"id": "T1218.005", "name": "System Binary Proxy Execution: Mshta"},
    "mshta.exe http":   {"id": "T1218.005", "name": "System Binary Proxy Execution: Mshta"},
    "mshta vbscript":   {"id": "T1218.005", "name": "System Binary Proxy Execution: Mshta"},
    "mshta javascript": {"id": "T1218.005", "name": "System Binary Proxy Execution: Mshta"},

    # -----------------------------------------------------------------
    # Privilege escalation (U2R)
    # -----------------------------------------------------------------

    "net localgroup administrators":      {"id": "T1098", "name": "Account Manipulation"},
    "net localgroup administrators /add": {"id": "T1098", "name": "Account Manipulation"},
    "whoami /priv":   {"id": "T1033", "name": "System Owner/User Discovery"},
    "whoami /groups": {"id": "T1033", "name": "System Owner/User Discovery"},
    "schtasks /ru system":       {"id": "T1053.005", "name": "Scheduled Task"},
    "runas /user:administrator": {"id": "T1548.002", "name": "Bypass User Account Control"},
    "fodhelper.exe":        {"id": "T1548.002", "name": "Bypass User Account Control"},
    "eventvwr.exe":         {"id": "T1548.002", "name": "Bypass User Account Control"},
    "computerdefaults.exe": {"id": "T1548.002", "name": "Bypass User Account Control"},
    "sdclt.exe":            {"id": "T1548.002", "name": "Bypass User Account Control"},

    "sudo su":      {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
    "sudo -i":      {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
    "sudo bash":    {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
    "sudo /bin/sh": {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
    "pkexec":       {"id": "T1548.001", "name": "Setuid and Setgid"},
    "chmod +s":     {"id": "T1548.001", "name": "Setuid and Setgid"},
    "chmod u+s":    {"id": "T1548.001", "name": "Setuid and Setgid"},
    "chmod 4777":   {"id": "T1548.001", "name": "Setuid and Setgid"},
    "chmod 4755":   {"id": "T1548.001", "name": "Setuid and Setgid"},
    "/etc/sudoers": {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
    "setuid":       {"id": "T1548.001", "name": "Setuid and Setgid"},

    # -----------------------------------------------------------------
    # Reconnaissance / brute force (R2L)
    # -----------------------------------------------------------------

    "nmap ":    {"id": "T1046", "name": "Network Service Discovery"},
    "nmap.exe": {"id": "T1046", "name": "Network Service Discovery"},
    "masscan":  {"id": "T1046", "name": "Network Service Discovery"},

    "hydra ":  {"id": "T1110", "name": "Brute Force"},
    "hydra -": {"id": "T1110", "name": "Brute Force"},
    "medusa -": {"id": "T1110", "name": "Brute Force"},
    "ncrack ": {"id": "T1110", "name": "Brute Force"},

    "ssh -":       {"id": "T1021.004", "name": "Remote Services: SSH"},
    "sshpass":     {"id": "T1110", "name": "Brute Force"},
    "patator ssh": {"id": "T1110", "name": "Brute Force"},

    "sqlmap":      {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "metasploit":  {"id": "T1588.002", "name": "Obtain Capabilities: Tool"},
    "msfconsole":  {"id": "T1588.002", "name": "Obtain Capabilities: Tool"},
    "msfvenom":    {"id": "T1588.002", "name": "Obtain Capabilities: Tool"},
    "aircrack-ng": {"id": "T1110", "name": "Brute Force"},
    "john ":       {"id": "T1110.002", "name": "Password Cracking"},
    "hashcat":     {"id": "T1110.002", "name": "Password Cracking"},

    # -----------------------------------------------------------------
    # Reverse shells / remote command channels
    # -----------------------------------------------------------------

    "nc -e":     {"id": "T1059", "name": "Command and Scripting Interpreter"},
    "nc.exe -e": {"id": "T1059", "name": "Command and Scripting Interpreter"},
    "ncat -e":   {"id": "T1059", "name": "Command and Scripting Interpreter"},
    "nc -lvnp":  {"id": "T1571", "name": "Non-Standard Port"},
    "nc -nlvp":  {"id": "T1571", "name": "Non-Standard Port"},
    "-lvnp":     {"id": "T1571", "name": "Non-Standard Port"},

    "/dev/tcp/": {"id": "T1059.004", "name": "Unix Shell"},
    "/dev/udp/": {"id": "T1059.004", "name": "Unix Shell"},
    "bash -i":   {"id": "T1059.004", "name": "Unix Shell"},
    "sh -i":     {"id": "T1059.004", "name": "Unix Shell"},

    "socket.socket":    {"id": "T1059.006", "name": "Python"},
    "socket(socket.":   {"id": "T1059.006", "name": "Python"},
    "pty.spawn":        {"id": "T1059.006", "name": "Python"},
    "os.dup2":          {"id": "T1059.006", "name": "Python"},
    "fsockopen":        {"id": "T1059", "name": "Command and Scripting Interpreter"},
    "socket.io.socket": {"id": "T1059", "name": "Command and Scripting Interpreter"},
    "new-object system.net.sockets.tcpclient":
        {"id": "T1059.001", "name": "PowerShell"},
    "powercat":         {"id": "T1059.001", "name": "PowerShell"},

    # -----------------------------------------------------------------
    # Ransomware / destructive impact
    # -----------------------------------------------------------------

    "vssadmin delete shadows":     {"id": "T1490", "name": "Inhibit System Recovery"},
    "vssadmin.exe delete shadows": {"id": "T1490", "name": "Inhibit System Recovery"},
    "wmic shadowcopy delete":      {"id": "T1490", "name": "Inhibit System Recovery"},
    "wbadmin delete catalog":      {"id": "T1490", "name": "Inhibit System Recovery"},
    "wbadmin delete backup":       {"id": "T1490", "name": "Inhibit System Recovery"},
    "bcdedit /set":                {"id": "T1490", "name": "Inhibit System Recovery"},
    "recoveryenabled no":          {"id": "T1490", "name": "Inhibit System Recovery"},
    "bootstatuspolicy ignoreallfailures":
        {"id": "T1490", "name": "Inhibit System Recovery"},
    "cipher /w":                   {"id": "T1485", "name": "Data Destruction"},
    "fsutil usn deletejournal":    {"id": "T1070", "name": "Indicator Removal"},

    "shred -":         {"id": "T1485", "name": "Data Destruction"},
    "rm -rf /":        {"id": "T1485", "name": "Data Destruction"},
    "dd if=/dev/zero": {"id": "T1485", "name": "Data Destruction"},

    # -----------------------------------------------------------------
    # Sensitive credential / secret store access
    # -----------------------------------------------------------------

    "reg save hklm\\sam":        {"id": "T1003.002", "name": "Security Account Manager"},
    "reg save hklm\\system":     {"id": "T1003.002", "name": "Security Account Manager"},
    "reg save hklm\\security":   {"id": "T1003.004", "name": "LSA Secrets"},
    "\\windows\\ntds\\ntds.dit": {"id": "T1003.003", "name": "NTDS"},
    "sekurlsa":                  {"id": "T1003.001", "name": "LSASS Memory"},
    "lsadump":                   {"id": "T1003.004", "name": "LSA Secrets"},
    "mimikatz":                  {"id": "T1003", "name": "OS Credential Dumping"},
    "comsvcs.dll, minidump":     {"id": "T1003.001", "name": "LSASS Memory"},
    "procdump":                  {"id": "T1003.001", "name": "LSASS Memory"},
    "lsass.dmp":                 {"id": "T1003.001", "name": "LSASS Memory"},
    "-ma lsass":                 {"id": "T1003.001", "name": "LSASS Memory"},

    "\\login data":  {"id": "T1555.003", "name": "Credentials from Web Browsers"},
    "\\logins.json": {"id": "T1555.003", "name": "Credentials from Web Browsers"},
    "vaultcmd":      {"id": "T1555.004", "name": "Windows Credential Manager"},
    ".kdbx":         {"id": "T1555.005", "name": "Password Managers"},

    "/etc/shadow":       {"id": "T1003.008", "name": "/etc/passwd and /etc/shadow"},
    "/etc/passwd":       {"id": "T1003.008", "name": "/etc/passwd and /etc/shadow"},
    "/.ssh/id_rsa":      {"id": "T1552.004", "name": "Private Keys"},
    "id_rsa":            {"id": "T1552.004", "name": "Private Keys"},
    "/.aws/credentials": {"id": "T1552.001", "name": "Credentials In Files"},
    "login.keychain":    {"id": "T1555.001", "name": "Keychain"},

    # -----------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------

    "schtasks /create":    {"id": "T1053.005", "name": "Scheduled Task"},
    "reg add":             {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
    "currentversion\\run": {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
    "sc create":           {"id": "T1543.003", "name": "Windows Service"},
    "new-service":         {"id": "T1543.003", "name": "Windows Service"},

    "crontab -":        {"id": "T1053.003", "name": "Cron"},
    "/etc/cron":        {"id": "T1053.003", "name": "Cron"},
    "systemctl enable": {"id": "T1543.002", "name": "Systemd Service"},
    ".bashrc":          {"id": "T1546.004", "name": "Unix Shell Configuration Modification"},

    "launchctl load": {"id": "T1543.001", "name": "Launch Agent"},
    "launchagents":   {"id": "T1543.001", "name": "Launch Agent"},
    "osascript -e":   {"id": "T1059.002", "name": "AppleScript"},
    "do shell script": {"id": "T1059.002", "name": "AppleScript"},
}


# =====================================================================
# Context-derived techniques
#
# derived_event_type -> technique
#
# These detections come from execution context (path, parent process,
# file name) rather than a command-line keyword, so they are keyed by
# the derived event type the classifier emits.
# =====================================================================

CONTEXT_MITRE = {

    "USB_EXECUTABLE_RUN": {
        "id": "T1091",
        "name": "Replication Through Removable Media",
    },

    "DOUBLE_EXTENSION": {
        "id": "T1036.007",
        "name": "Masquerading: Double File Extension",
    },

    "OFFICE_SPAWNED_SHELL": {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
    },

    "UNSIGNED_BINARY": {
        "id": "T1036.001",
        "name": "Masquerading: Invalid Code Signature",
    },

    "SUSPICIOUS_DOWNLOAD": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
    },

    # ---- network plane (Suricata) ---------------------------------

    "NETWORK_ALERT": {
        "id": "T1071",
        "name": "Application Layer Protocol",
    },

    "PORT_SCAN": {
        "id": "T1046",
        "name": "Network Service Discovery",
    },

    "MALICIOUS_IP_CONTACT": {
        "id": "T1071",
        "name": "Application Layer Protocol (C2)",
    },

    "DATA_EXFILTRATION": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
    },

    "C2_BEACONING": {
        "id": "T1071",
        "name": "Application Layer Protocol (C2 beaconing)",
    },

    "DNS_TUNNELING": {
        "id": "T1071.004",
        "name": "Application Layer Protocol: DNS",
    },

    # ---- SIEM plane (Wazuh) ---------------------------------------

    "SIEM_ALERT": {
        "id": "T1078",
        "name": "SIEM Rule Match",
    },
}
