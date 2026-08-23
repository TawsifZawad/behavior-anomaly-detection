from specs.network_rules import (
    NETWORK_CATEGORY_RULES,
    DEFAULT_ALERT_WEIGHT,
    DEFAULT_ALERT_EVENT,
    SEVERITY_MULTIPLIER,
    EXFIL_BYTES_THRESHOLD,
    PRIVATE_IP_PREFIXES,
)
from specs.mitre_rules import CONTEXT_MITRE


class NetworkDetector:
    """
    Context-aware classifier for one Suricata eve.json record.

    Mirrors ProcessDetector / FileDetector on the network plane. Given a
    parsed eve.json object it returns the normalized network event types
    the FeatureExtractor understands (NETWORK_ALERT, PORT_SCAN,
    MALICIOUS_IP_CONTACT, DATA_EXFILTRATION) together with a risk score
    and MITRE techniques, or None for records we do not model
    (benign flows, dns, tls handshakes, ...).

    Two kinds of eve records are modelled:
      * `alert`  — a signature fired; category + severity drive scoring.
      * `flow`   — a completed flow; a large outbound transfer to a
                   non-private destination is flagged as exfiltration
                   with no signature required.
    """

    def _is_private(self, ip):
        if not ip:
            return True  # unknown destination -> don't flag as egress
        return any(str(ip).startswith(p) for p in PRIVATE_IP_PREFIXES)

    def analyze(self, record):

        if not isinstance(record, dict):
            return None

        event_type = record.get("event_type")

        if event_type == "alert":
            return self._analyze_alert(record)

        if event_type == "flow":
            return self._analyze_flow(record)

        return None

    # ------------------------------------------------------------------

    def _analyze_alert(self, record):

        alert = record.get("alert", {}) or {}

        category = (alert.get("category") or "").lower()
        severity = alert.get("severity", 2)
        signature = alert.get("signature", "")

        weight = None
        derived = DEFAULT_ALERT_EVENT

        for needle, (rule_weight, event_type) in NETWORK_CATEGORY_RULES.items():
            if needle in category:
                weight = rule_weight
                derived = event_type
                break

        if weight is None:
            weight = DEFAULT_ALERT_WEIGHT
            derived = DEFAULT_ALERT_EVENT

        multiplier = SEVERITY_MULTIPLIER.get(severity, 0.7)
        score = int(round(weight * multiplier))

        mitre = []
        if derived in CONTEXT_MITRE:
            mitre.append(CONTEXT_MITRE[derived])

        return {
            "score": score,
            "derived_events": [derived],
            "mitre": mitre,
            "signature": signature,
            "category": category,
            "src_ip": record.get("src_ip"),
            "dest_ip": record.get("dest_ip"),
        }

    # ------------------------------------------------------------------

    def _analyze_flow(self, record):

        flow = record.get("flow", {}) or {}

        bytes_out = flow.get("bytes_toserver", 0) or 0
        dest_ip = record.get("dest_ip")

        # Only outbound transfers leaving the local network are of
        # interest; internal backups etc. are ignored.
        if bytes_out < EXFIL_BYTES_THRESHOLD or self._is_private(dest_ip):
            return None

        mitre = []
        if "DATA_EXFILTRATION" in CONTEXT_MITRE:
            mitre.append(CONTEXT_MITRE["DATA_EXFILTRATION"])

        # Scale score with volume (cap so a single huge transfer can't
        # dominate the whole session score).
        over = bytes_out / EXFIL_BYTES_THRESHOLD
        score = min(70, int(40 + 10 * over))

        return {
            "score": score,
            "derived_events": ["DATA_EXFILTRATION"],
            "mitre": mitre,
            "signature": f"large outbound flow ({bytes_out} bytes)",
            "category": "flow-exfiltration",
            "src_ip": record.get("src_ip"),
            "dest_ip": dest_ip,
        }
