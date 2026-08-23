# =====================================================================
# Wazuh (SIEM / HIDS) alert classification rules
#
# Wazuh writes one JSON alert per line to alerts.json. Each alert has a
# `rule` object with a numeric `level` (0-15, higher = more severe),
# a `description`, `groups` (e.g. "sshd", "authentication_failed",
# "privilege_escalation"), and often a `mitre` block Wazuh has already
# mapped.
#
# We reuse Wazuh's rule groups to reinforce our EXISTING normalized
# event types (so a Wazuh brute-force alert boosts the same host feature
# our own collectors would), and additionally emit a generic SIEM_ALERT
# for the rule-engine verdict itself. Wazuh's own MITRE ids are reused
# directly when present.
#
# Matching is on a lowercased substring of any rule group, robust across
# Wazuh ruleset versions.
# =====================================================================


# rule-group substring -> derived event type that our extractor already
# understands. These reinforce host-plane features cross-source.
WAZUH_GROUP_TO_EVENT = {

    "authentication_failed":   "LOGIN_FAILED",
    "authentication_failures": "LOGIN_FAILED",
    "win_authentication_failed": "LOGIN_FAILED",
    "invalid_login":           "LOGIN_FAILED",

    "authentication_success":  "LOGIN_SUCCESS",

    "privilege_escalation":    "PRIVILEGE_ESCALATION",
    "sudo":                    "SUDO_ABUSE",

    "ssh_bruteforce":          "SSH_BRUTEFORCE",
    "sshd_brute_force":        "SSH_BRUTEFORCE",

    "rootcheck":               "PERSISTENCE_CREATED",
    "rootkit":                 "PERSISTENCE_CREATED",

    "web_scan":                "PORT_SCAN",
    "recon":                   "PORT_SCAN",

    "data_exfiltration":       "DATA_EXFILTRATION",
}


# A brute-force verdict is often expressed only in the description
# ("maximum authentication attempts exceeded"), not a dedicated group.
WAZUH_DESCRIPTION_TO_EVENT = {
    "maximum authentication attempts exceeded": "SSH_BRUTEFORCE",
    "multiple authentication failures":          "SSH_BRUTEFORCE",
    "brute force":                               "SSH_BRUTEFORCE",
    "possible attack on the ssh server":         "SSH_BRUTEFORCE",
}


# Only alerts at or above this Wazuh level are ingested; lower levels are
# routine noise (e.g. successful logins, informational decoder matches).
MIN_ALERT_LEVEL = 5

# The generic SIEM_ALERT score scales with Wazuh level (level 15 -> 60),
# so a critical Wazuh rule outranks a minor one. Capped.
def level_to_score(level):
    try:
        level = int(level)
    except (TypeError, ValueError):
        level = 0
    return min(60, level * 4)
