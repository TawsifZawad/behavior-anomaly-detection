# =====================================================================
# Command-line classification rules
#
# Each rule maps a lowercase keyword to:
#   (risk_weight, derived_event_type)
#
# The derived_event_type is the normalized Event.event_type that the
# FeatureExtractor already understands (see feature_engine/extractor.py).
# The classifier (core/process_detector.py) scans a command line, sums
# the weights, and emits one derived event per matched rule group.
#
# Rules are grouped only for readability. POWERSHELL_SUSPICIOUS_KEYWORDS
# is preserved for backward compatibility (older code imported it as a
# flat keyword -> weight map).
# =====================================================================


# ---------------------------------------------------------------------
# PowerShell / script abuse
# ---------------------------------------------------------------------

POWERSHELL_RULES = {

    "-executionpolicy bypass": (20, "EXECUTION_POLICY_BYPASS"),
    "-exec bypass":            (20, "EXECUTION_POLICY_BYPASS"),
    "-ep bypass":              (20, "EXECUTION_POLICY_BYPASS"),

    "-encodedcommand": (50, "ENCODED_COMMAND"),
    "-enc ":           (50, "ENCODED_COMMAND"),
    # PowerShell-scoped "-e" short form only. A bare "-e " matched too
    # broadly (osascript -e, nc -e, ping -e), so it is qualified with the
    # interpreter name to avoid cross-tool false positives.
    "powershell -e ":     (30, "ENCODED_COMMAND"),
    "powershell.exe -e ": (30, "ENCODED_COMMAND"),
    "pwsh -e ":           (30, "ENCODED_COMMAND"),
    "frombase64string": (40, "ENCODED_COMMAND"),

    "invoke-expression": (40, "POWERSHELL_START"),
    "iex ":              (40, "POWERSHELL_START"),
    "invoke-command":    (30, "POWERSHELL_START"),
    "reflection.assembly": (50, "POWERSHELL_START"),

    "downloadstring":            (40, "INTERNET_DOWNLOAD"),
    "downloadfile":              (40, "INTERNET_DOWNLOAD"),
    "invoke-webrequest":         (30, "INTERNET_DOWNLOAD"),
    "start-bitstransfer":        (30, "INTERNET_DOWNLOAD"),
    "new-object net.webclient":  (40, "INTERNET_DOWNLOAD"),
    "system.net.webclient":      (40, "INTERNET_DOWNLOAD"),
    "curl ":                     (20, "INTERNET_DOWNLOAD"),
    "wget ":                     (20, "INTERNET_DOWNLOAD"),

    "-windowstyle hidden": (30, "HIDDEN_PROCESS"),
    "-w hidden":           (30, "HIDDEN_PROCESS"),

    "-nop":            (25, "POWERSHELL_START"),
    "-noprofile":      (20, "POWERSHELL_START"),
    "-noninteractive": (20, "POWERSHELL_START"),
    "-noni":           (20, "POWERSHELL_START"),

    "add-mppreference": (60, "POWERSHELL_START"),
    "set-mppreference": (60, "POWERSHELL_START"),
}


# Backward-compatible flat map: keyword -> weight
# (kept so any existing import of POWERSHELL_SUSPICIOUS_KEYWORDS still works)
POWERSHELL_SUSPICIOUS_KEYWORDS = {
    keyword: weight
    for keyword, (weight, _event) in POWERSHELL_RULES.items()
}


# ---------------------------------------------------------------------
# LOLBins (living-off-the-land binaries, Windows)
# ---------------------------------------------------------------------

LOLBIN_RULES = {

    "certutil -urlcache": (50, "CERTUTIL_DOWNLOAD"),
    "certutil.exe -urlcache": (50, "CERTUTIL_DOWNLOAD"),
    "certutil -decode":   (40, "CERTUTIL_DOWNLOAD"),
    "-urlcache -split":   (50, "CERTUTIL_DOWNLOAD"),

    "bitsadmin /transfer": (50, "BITSADMIN_DOWNLOAD"),
    "bitsadmin.exe /transfer": (50, "BITSADMIN_DOWNLOAD"),

    "rundll32 javascript": (60, "RUNDLL32_NETWORK"),
    "rundll32.exe javascript": (60, "RUNDLL32_NETWORK"),
    "rundll32 http":       (50, "RUNDLL32_NETWORK"),

    "regsvr32 /i:http":  (60, "REGSVR32_REMOTE_SCRIPT"),
    "regsvr32 /u /i:":   (50, "REGSVR32_REMOTE_SCRIPT"),
    "scrobj.dll":        (50, "REGSVR32_REMOTE_SCRIPT"),

    "mshta http":        (60, "MSHTA_REMOTE_SCRIPT"),
    "mshta.exe http":    (60, "MSHTA_REMOTE_SCRIPT"),
    "mshta vbscript":    (60, "MSHTA_REMOTE_SCRIPT"),
    "mshta javascript":  (60, "MSHTA_REMOTE_SCRIPT"),
}


# ---------------------------------------------------------------------
# U2R — privilege escalation
# ---------------------------------------------------------------------

PRIVILEGE_ESCALATION_RULES = {

    # Windows
    "net localgroup administrators": (60, "PRIVILEGE_ESCALATION"),
    "net localgroup administrators /add": (70, "PRIVILEGE_ESCALATION"),
    "whoami /priv":                  (20, "PRIVILEGE_ESCALATION"),
    "whoami /groups":                (15, "PRIVILEGE_ESCALATION"),
    "schtasks /ru system":           (50, "PRIVILEGE_ESCALATION"),
    "runas /user:administrator":     (40, "PRIVILEGE_ESCALATION"),
    "fodhelper.exe":                 (60, "PRIVILEGE_ESCALATION"),
    "eventvwr.exe":                  (50, "PRIVILEGE_ESCALATION"),
    "computerdefaults.exe":          (50, "PRIVILEGE_ESCALATION"),
    "sdclt.exe":                     (50, "PRIVILEGE_ESCALATION"),

    # Linux
    "sudo su":       (40, "SUDO_ABUSE"),
    "sudo -i":       (40, "SUDO_ABUSE"),
    "sudo bash":     (50, "SUDO_ABUSE"),
    "sudo /bin/sh":  (50, "SUDO_ABUSE"),
    "pkexec":        (40, "PRIVILEGE_ESCALATION"),
    "chmod +s":      (50, "PRIVILEGE_ESCALATION"),
    "chmod u+s":     (50, "PRIVILEGE_ESCALATION"),
    "chmod 4777":    (50, "PRIVILEGE_ESCALATION"),
    "chmod 4755":    (50, "PRIVILEGE_ESCALATION"),
    "/etc/sudoers":  (50, "PRIVILEGE_ESCALATION"),
    "setuid":        (40, "PRIVILEGE_ESCALATION"),
}


# ---------------------------------------------------------------------
# R2L — remote-to-local tooling / reconnaissance / brute force
# ---------------------------------------------------------------------

RECON_RULES = {

    "nmap ":       (40, "NMAP_SCAN"),
    "nmap.exe":    (40, "NMAP_SCAN"),
    "masscan":     (40, "NMAP_SCAN"),

    "hydra ":      (60, "HYDRA_BRUTEFORCE"),
    "hydra -":     (60, "HYDRA_BRUTEFORCE"),
    "medusa -":    (60, "HYDRA_BRUTEFORCE"),
    "ncrack ":     (60, "HYDRA_BRUTEFORCE"),

    "ssh -":            (20, "SSH_BRUTEFORCE"),
    "sshpass":          (50, "SSH_BRUTEFORCE"),
    "patator ssh":      (60, "SSH_BRUTEFORCE"),

    # attack tooling (recon / cracking / exploitation)
    "sqlmap":       (50, "NMAP_SCAN"),
    "metasploit":   (60, "NMAP_SCAN"),
    "msfconsole":   (60, "NMAP_SCAN"),
    "msfvenom":     (60, "NMAP_SCAN"),
    "aircrack-ng":  (50, "NMAP_SCAN"),
    "john ":        (50, "HYDRA_BRUTEFORCE"),
    "hashcat":      (50, "HYDRA_BRUTEFORCE"),
}


# ---------------------------------------------------------------------
# Reverse shells / remote command channels
# ---------------------------------------------------------------------

REVERSE_SHELL_RULES = {

    # netcat listeners / connect-back
    "nc -e":        (60, "REVERSE_SHELL"),
    "nc.exe -e":    (60, "REVERSE_SHELL"),
    "ncat -e":      (60, "REVERSE_SHELL"),
    "nc -lvnp":     (50, "REVERSE_SHELL"),
    "nc -nlvp":     (50, "REVERSE_SHELL"),
    "-lvnp":        (40, "REVERSE_SHELL"),

    # bash / sh built-in TCP redirection
    "/dev/tcp/":    (60, "REVERSE_SHELL"),
    "/dev/udp/":    (60, "REVERSE_SHELL"),
    "bash -i":      (40, "REVERSE_SHELL"),
    "sh -i":        (30, "REVERSE_SHELL"),

    # interpreter socket one-liners
    "socket.socket":      (40, "REVERSE_SHELL"),
    "socket(socket.":     (40, "REVERSE_SHELL"),
    "pty.spawn":          (50, "REVERSE_SHELL"),
    "os.dup2":            (40, "REVERSE_SHELL"),
    "fsockopen":          (50, "REVERSE_SHELL"),
    "socket.io.socket":   (30, "REVERSE_SHELL"),
    "new-object system.net.sockets.tcpclient": (50, "REVERSE_SHELL"),
    "powercat":           (50, "REVERSE_SHELL"),
}


# ---------------------------------------------------------------------
# Ransomware / destructive impact (T1490 inhibit recovery, T1486)
# ---------------------------------------------------------------------

RANSOMWARE_RULES = {

    # Windows: destroy backups / recovery so files can't be restored
    "vssadmin delete shadows":   (70, "RANSOMWARE_BEHAVIOR"),
    "vssadmin.exe delete shadows": (70, "RANSOMWARE_BEHAVIOR"),
    "wmic shadowcopy delete":    (70, "RANSOMWARE_BEHAVIOR"),
    "wbadmin delete catalog":    (60, "RANSOMWARE_BEHAVIOR"),
    "wbadmin delete backup":     (60, "RANSOMWARE_BEHAVIOR"),
    "bcdedit /set":              (30, "RANSOMWARE_BEHAVIOR"),
    "recoveryenabled no":        (50, "RANSOMWARE_BEHAVIOR"),
    "bootstatuspolicy ignoreallfailures": (50, "RANSOMWARE_BEHAVIOR"),
    "cipher /w":                 (50, "RANSOMWARE_BEHAVIOR"),
    "fsutil usn deletejournal":  (50, "RANSOMWARE_BEHAVIOR"),

    # Linux
    "shred -":                   (40, "RANSOMWARE_BEHAVIOR"),
    "rm -rf /":                  (50, "RANSOMWARE_BEHAVIOR"),
    "dd if=/dev/zero":           (40, "RANSOMWARE_BEHAVIOR"),
}


# ---------------------------------------------------------------------
# Sensitive credential / secret store access (T1003, T1552, T1555)
# ---------------------------------------------------------------------

SENSITIVE_FILE_RULES = {

    # Windows credential stores
    "reg save hklm\\sam":      (70, "SENSITIVE_FILE_ACCESS"),
    "reg save hklm\\system":   (60, "SENSITIVE_FILE_ACCESS"),
    "reg save hklm\\security": (60, "SENSITIVE_FILE_ACCESS"),
    "\\windows\\ntds\\ntds.dit": (70, "SENSITIVE_FILE_ACCESS"),
    "sekurlsa":                (70, "SENSITIVE_FILE_ACCESS"),
    "lsadump":                 (70, "SENSITIVE_FILE_ACCESS"),
    "mimikatz":                (70, "SENSITIVE_FILE_ACCESS"),
    "comsvcs.dll, minidump":   (70, "SENSITIVE_FILE_ACCESS"),
    "procdump":                (40, "SENSITIVE_FILE_ACCESS"),
    "lsass.dmp":               (60, "SENSITIVE_FILE_ACCESS"),
    "-ma lsass":               (70, "SENSITIVE_FILE_ACCESS"),

    # Browser / password manager stores
    "\\login data":            (40, "SENSITIVE_FILE_ACCESS"),
    "\\logins.json":           (40, "SENSITIVE_FILE_ACCESS"),
    "vaultcmd":                (40, "SENSITIVE_FILE_ACCESS"),
    ".kdbx":                   (30, "SENSITIVE_FILE_ACCESS"),

    # Linux / macOS secrets
    "/etc/shadow":             (60, "SENSITIVE_FILE_ACCESS"),
    "/etc/passwd":             (30, "SENSITIVE_FILE_ACCESS"),
    "/.ssh/id_rsa":            (60, "SENSITIVE_FILE_ACCESS"),
    "id_rsa":                  (40, "SENSITIVE_FILE_ACCESS"),
    "/.aws/credentials":       (50, "SENSITIVE_FILE_ACCESS"),
    "login.keychain":          (50, "SENSITIVE_FILE_ACCESS"),
}


# ---------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------

PERSISTENCE_RULES = {

    # Windows
    "schtasks /create":  (40, "PERSISTENCE_CREATED"),
    "reg add":           (20, "PERSISTENCE_CREATED"),
    "currentversion\\run": (50, "PERSISTENCE_CREATED"),
    "sc create":         (40, "PERSISTENCE_CREATED"),
    "new-service":       (40, "PERSISTENCE_CREATED"),

    # Linux
    "crontab -":         (40, "PERSISTENCE_CREATED"),
    "/etc/cron":         (40, "PERSISTENCE_CREATED"),
    "systemctl enable":  (20, "PERSISTENCE_CREATED"),
    ".bashrc":           (20, "PERSISTENCE_CREATED"),

    # macOS
    "launchctl load":    (40, "PERSISTENCE_CREATED"),
    "launchagents":      (40, "PERSISTENCE_CREATED"),
    "osascript -e":      (40, "OSASCRIPT_SHELL"),
    "do shell script":   (50, "OSASCRIPT_SHELL"),
}


# ---------------------------------------------------------------------
# Execution-from-temp path heuristics
# (matched against the executable path, not only the command line)
# ---------------------------------------------------------------------

TEMP_PATH_MARKERS = [
    "\\temp\\",
    "\\appdata\\local\\temp",
    "\\windows\\temp",
    "\\downloads\\",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm",
]


# ---------------------------------------------------------------------
# Removable-media mount points (Linux / macOS).
# Windows removable drives cannot be listed statically: the collector
# resolves the active USB drive letters at collection time and passes
# them to ProcessDetector.analyze(usb_drives=...).
# ---------------------------------------------------------------------

REMOVABLE_MEDIA_MARKERS = [
    "/media/",       # Ubuntu / Debian auto-mount
    "/run/media/",   # Fedora / systemd auto-mount
    "/mnt/usb",      # manual mounts
    "/volumes/",     # macOS external volumes
]


# ---------------------------------------------------------------------
# Parent-child process context.
# A document application spawning a shell / script interpreter is the
# classic phishing-macro execution chain (T1204.002).
# ---------------------------------------------------------------------

OFFICE_PARENT_PROCESSES = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "mspub.exe",
    "onenote.exe",
    "acrord32.exe",
    "acrobat.exe",
    "foxitreader.exe",
}

OFFICE_SUSPICIOUS_CHILDREN = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}


# ---------------------------------------------------------------------
# Double-extension masquerading (invoice.pdf.exe).
# A harmless-looking document/media extension immediately followed by
# an executable extension in the file name.
# ---------------------------------------------------------------------

DECOY_EXTENSIONS = (
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "bmp",
    "mp3", "mp4", "avi", "zip", "rar",
)

EXECUTABLE_EXTENSIONS = (
    "exe", "scr", "com", "pif",
    "bat", "cmd", "vbs", "vbe", "js", "jse",
    "ps1", "msi", "jar", "hta",
)


# ---------------------------------------------------------------------
# Suspicious file drop / download.
# A file with an executable / script / container extension created in
# a download, temp, desktop or removable location is treated as a
# suspicious download (the honest signal that a payload landed on
# disk, independent of whether it has run yet).
# ---------------------------------------------------------------------

DROP_PATH_MARKERS = [
    "\\downloads\\",
    "\\desktop\\",
    "\\temp\\",
    "\\appdata\\local\\temp",
    "\\appdata\\roaming",
    "\\windows\\temp",
    "\\public\\",
    "/downloads/",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm",
    "/media/",
    "/run/media/",
    "/volumes/",
]

# Extensions that, when dropped into one of the locations above, make
# the file a suspicious download. Superset of EXECUTABLE_EXTENSIONS
# plus containers commonly used to smuggle payloads past mail filters
# and common Linux/macOS payload types. (Extension-less Linux binaries
# cannot be caught here; the chmod/curl command-line rules cover that
# delivery path instead.)
DROPPED_FILE_EXTENSIONS = EXECUTABLE_EXTENSIONS + (
    "dll", "cpl", "lnk", "iso", "img", "vhd", "vhdx",
    "sh", "elf", "run", "bin", "appimage", "deb", "rpm",
)


# ---------------------------------------------------------------------
# Derived events that justify the (relatively expensive) Authenticode
# signature check on the executable. Presence-only process starts are
# never signature-checked — only executions from an already-suspicious
# location or with a masquerading name.
# ---------------------------------------------------------------------

SIGNATURE_CHECK_TRIGGERS = {
    "EXECUTION_FROM_TEMP",
    "USB_EXECUTABLE_RUN",
    "DOUBLE_EXTENSION",
    "DOWNLOAD_EXECUTE",
}


# ---------------------------------------------------------------------
# Aggregate list of all keyword rule groups the classifier scans.
# Order matters only for readability; scoring is additive.
# ---------------------------------------------------------------------

ALL_RULE_GROUPS = [
    POWERSHELL_RULES,
    LOLBIN_RULES,
    PRIVILEGE_ESCALATION_RULES,
    RECON_RULES,
    REVERSE_SHELL_RULES,
    RANSOMWARE_RULES,
    SENSITIVE_FILE_RULES,
    PERSISTENCE_RULES,
]


# Processes that are, by themselves, worth attention ("concern" tier)
# even with a clean command line.
INTERPRETER_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "bash",
    "sh",
    "zsh",
    "python.exe",
    "python",
}
