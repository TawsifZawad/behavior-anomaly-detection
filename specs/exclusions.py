# =====================================================================
# Allowlist / exclusion policy
#
# Operator-tunable list of known-good processes / commands that are
# suppressed BEFORE threat classification — mirroring the exclusion
# policies of enterprise EDR/SIEM (Defender, CrowdStrike, Wazuh). This
# cuts false positives from the security tool's own operations and from
# trusted administrative / CI activity, WITHOUT weakening the underlying
# detection: everything not on the list is still fully analysed.
#
# Matching is a case-insensitive substring test over the executable image
# path + command line. Keep entries specific enough that an attacker
# cannot trivially ride on them.
# =====================================================================


# --- Self-exclusion -------------------------------------------------
# The monitor must not alert on itself running, building or packaging.
SELF_EXCLUSIONS = [
    "bads.py",
    "bads.exe",
    "windows-demo",
    "linux-demo",
    "macos-demo",
    "\\software\\",
    "pyinstaller",
    "--name windows-demo",
    "--name bads",
    "collect-submodules sklearn",
]


# --- Operator allowlist ---------------------------------------------
# Add your organisation's known-good administrative / automation
# patterns here (empty by default). Examples left commented.
OPERATOR_ALLOWLIST = [
    # "\\jenkins\\",
    # "deploy.ps1",
    # "c:\\program files\\trusted-agent\\",
]


EXCLUSION_PATTERNS = [
    p.lower() for p in (SELF_EXCLUSIONS + OPERATOR_ALLOWLIST) if p
]


def is_excluded(image_path, command_line):
    """
    True if this process image / command matches a trusted allowlist
    entry and should be suppressed from threat classification.
    """
    haystack = (str(image_path or "") + " " + str(command_line or "")).lower()
    return any(pattern in haystack for pattern in EXCLUSION_PATTERNS)
