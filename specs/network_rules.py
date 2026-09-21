# =====================================================================
# Suricata (network IDS) classification rules
#
# Suricata writes one JSON object per line to eve.json. Alert records
# carry an `alert.category` string (from Suricata's classification.config)
# and an `alert.severity` (1 = most severe ... 3 = least). We map the
# category to one of our normalized network event types the
# FeatureExtractor understands, so a network-plane verdict flows through
# the same pipeline as host-plane behavior.
#
# Matching is done on a lowercased substring of the category so it is
# robust across ruleset wording (ET Open, Snort VRT, custom rules).
# =====================================================================


# category substring -> (risk_weight, derived_event_type)
NETWORK_CATEGORY_RULES = {

    # ---- reconnaissance -------------------------------------------
    "network scan":       (40, "PORT_SCAN"),
    "network-scan":       (40, "PORT_SCAN"),
    "attempted information leak": (30, "PORT_SCAN"),

    # ---- malware / command-and-control ----------------------------
    "trojan":                 (70, "MALICIOUS_IP_CONTACT"),
    "command and control":    (70, "MALICIOUS_IP_CONTACT"),
    "malware command":        (70, "MALICIOUS_IP_CONTACT"),
    "domain observed used for c2": (70, "MALICIOUS_IP_CONTACT"),
    "exploit kit":            (70, "MALICIOUS_IP_CONTACT"),
    "targeted malicious":     (70, "MALICIOUS_IP_CONTACT"),
    "crypto currency mining": (60, "MALICIOUS_IP_CONTACT"),
    "coin mining":            (60, "MALICIOUS_IP_CONTACT"),

    # ---- exfiltration ---------------------------------------------
    "large scale information leak": (60, "DATA_EXFILTRATION"),
    "information leak":             (40, "DATA_EXFILTRATION"),

    # ---- exploitation / privilege ---------------------------------
    "administrator privilege gain": (60, "NETWORK_ALERT"),
    "user privilege gain":          (50, "NETWORK_ALERT"),
    "web application attack":       (40, "NETWORK_ALERT"),
    "denial of service":            (40, "NETWORK_ALERT"),
    "executable code was detected": (50, "NETWORK_ALERT"),
    "shellcode":                    (50, "NETWORK_ALERT"),
    "misc attack":                  (30, "NETWORK_ALERT"),
    "potentially bad traffic":      (20, "NETWORK_ALERT"),
}


# Any alert whose category matches none of the above still counts as a
# generic network IDS hit at this weight.
DEFAULT_ALERT_WEIGHT = 20
DEFAULT_ALERT_EVENT = "NETWORK_ALERT"


# Suricata severity (1 = high, 2 = medium, 3 = low) scales the weight so
# a high-severity signature outranks an informational one.
SEVERITY_MULTIPLIER = {
    1: 1.0,
    2: 0.7,
    3: 0.4,
}


# ---------------------------------------------------------------------
# Flow-based heuristics (no signature needed)
# ---------------------------------------------------------------------

# Outbound bytes on a single flow above this are treated as possible
# data exfiltration. 10 MB is deliberately conservative for a demo /
# thesis; tune per environment.
EXFIL_BYTES_THRESHOLD = 10 * 1024 * 1024

# Private/loopback destinations never count as exfiltration or malicious
# egress — only traffic leaving the local network is interesting here.
PRIVATE_IP_PREFIXES = (
    "10.",
    "192.168.",
    "127.",
    "0.",
    "::1",
    "fe80:",
    "169.254.",
) + tuple(f"172.{n}." for n in range(16, 32))


# ---------------------------------------------------------------------
# Network-BEHAVIOUR heuristics (no signature needed)
#
# These extend Suricata's signature layer with two behaviour-based
# detections the ruleset alone misses: C2 beaconing (periodic callbacks)
# and DNS tunnelling (data/command smuggled inside DNS query names).
# Both are computed from eve.json `dns` / `flow` records, not `alert`s.
# ---------------------------------------------------------------------

# ---- DNS tunnelling -------------------------------------------------
# A tunnelling client encodes payload into the query name, producing
# abnormally long, high-entropy labels and an unusually large query name.
# A single record is enough to flag when it is clearly anomalous.
DNS_TUNNEL_MIN_QNAME_LEN = 52     # total query-name length (chars)
DNS_TUNNEL_MIN_LABEL_LEN = 30     # length of the longest single label
DNS_TUNNEL_MIN_ENTROPY = 3.6      # Shannon entropy (bits/char) of that label
DNS_TUNNEL_WEIGHT = 60

# Query types most abused for tunnelling (large answer capacity).
DNS_TUNNEL_SUSPECT_TYPES = ("TXT", "NULL", "CNAME", "MX", "AAAA")

# ---- C2 beaconing ---------------------------------------------------
# A beacon calls home at a near-constant interval. Given the timestamps
# of repeated outbound connections to one external destination, a low
# coefficient of variation (std/mean) of the inter-arrival gaps, over
# enough hits, is the tell-tale of automation rather than human browsing.
BEACON_MIN_HITS = 6               # minimum callbacks to judge periodicity
BEACON_MAX_CV = 0.25              # max coefficient of variation of gaps
BEACON_MIN_INTERVAL = 5           # ignore bursts faster than this (seconds)
BEACON_WEIGHT = 60
