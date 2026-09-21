import math

from specs.network_rules import (
    NETWORK_CATEGORY_RULES,
    DEFAULT_ALERT_WEIGHT,
    DEFAULT_ALERT_EVENT,
    SEVERITY_MULTIPLIER,
    EXFIL_BYTES_THRESHOLD,
    PRIVATE_IP_PREFIXES,
    DNS_TUNNEL_MIN_QNAME_LEN,
    DNS_TUNNEL_MIN_LABEL_LEN,
    DNS_TUNNEL_MIN_ENTROPY,
    DNS_TUNNEL_WEIGHT,
    DNS_TUNNEL_SUSPECT_TYPES,
)
from specs.mitre_rules import CONTEXT_MITRE


def _shannon_entropy(text):
    """Bits-per-character Shannon entropy of a string (0 for empty)."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


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

        if event_type == "dns":
            return self._analyze_dns(record)

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

    # ------------------------------------------------------------------

    def _analyze_dns(self, record):
        """
        DNS-tunnelling heuristic on a `dns` query record.

        A tunnelling client hides payload in the query name, so we look
        for an abnormally long query name whose longest label is both
        long and high-entropy (encoded bytes rather than a real word).
        Only queries are considered (rrtype present, no answers yet).
        """

        dns = record.get("dns", {}) or {}

        # eve.json puts the queried name under `rrname`; on newer
        # versions a query object may sit under `queries`.
        rrname = dns.get("rrname") or ""
        rrtype = (dns.get("rrtype") or "").upper()
        if not rrname and isinstance(dns.get("queries"), list) and dns["queries"]:
            q0 = dns["queries"][0] or {}
            rrname = q0.get("rrname", "")
            rrtype = (q0.get("rrtype") or rrtype).upper()

        if not rrname or len(rrname) < DNS_TUNNEL_MIN_QNAME_LEN:
            return None

        labels = [l for l in rrname.split(".") if l]
        if not labels:
            return None
        longest = max(labels, key=len)

        entropy = _shannon_entropy(longest)
        if len(longest) < DNS_TUNNEL_MIN_LABEL_LEN or \
                entropy < DNS_TUNNEL_MIN_ENTROPY:
            return None

        # Abused query types raise confidence but are not required.
        score = DNS_TUNNEL_WEIGHT
        if rrtype in DNS_TUNNEL_SUSPECT_TYPES:
            score = min(75, score + 10)

        mitre = []
        if "DNS_TUNNELING" in CONTEXT_MITRE:
            mitre.append(CONTEXT_MITRE["DNS_TUNNELING"])

        return {
            "score": score,
            "derived_events": ["DNS_TUNNELING"],
            "mitre": mitre,
            "signature": (
                f"DNS tunnelling: {rrtype or 'query'} name len "
                f"{len(rrname)}, label entropy {entropy:.1f} "
                f"({rrname[:40]}...)"
            ),
            "category": "dns-tunnelling",
            "src_ip": record.get("src_ip"),
            "dest_ip": record.get("dest_ip"),
        }
