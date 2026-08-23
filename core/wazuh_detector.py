from specs.wazuh_rules import (
    WAZUH_GROUP_TO_EVENT,
    WAZUH_DESCRIPTION_TO_EVENT,
    MIN_ALERT_LEVEL,
    level_to_score,
)
from specs.mitre_rules import CONTEXT_MITRE


class WazuhDetector:
    """
    Context-aware classifier for one Wazuh alerts.json record.

    Mirrors ProcessDetector / FileDetector / NetworkDetector but on the
    SIEM plane. Given a parsed Wazuh alert it:

      * emits a generic SIEM_ALERT (the rule-engine verdict itself),
        scored by the Wazuh rule level;
      * reinforces an EXISTING host event type when the rule groups /
        description identify a known pattern (brute force, privilege
        escalation, sudo abuse, rootkit ...), so Wazuh corroborates the
        same feature our own collectors would set;
      * reuses Wazuh's own MITRE technique ids when the alert carries a
        `rule.mitre` block, falling back to our CONTEXT_MITRE otherwise.

    Returns the derived event types + score + MITRE, or None for alerts
    below MIN_ALERT_LEVEL.
    """

    def analyze(self, record):

        if not isinstance(record, dict):
            return None

        rule = record.get("rule", {}) or {}

        level = rule.get("level", 0)
        try:
            level_int = int(level)
        except (TypeError, ValueError):
            level_int = 0

        if level_int < MIN_ALERT_LEVEL:
            return None

        groups = [g.lower() for g in (rule.get("groups") or [])]
        description = (rule.get("description") or "").lower()

        derived = []

        def add(event_type):
            if event_type not in derived:
                derived.append(event_type)

        # The SIEM verdict itself is always recorded.
        add("SIEM_ALERT")

        # Reinforce a known host pattern where the groups identify one.
        for needle, event_type in WAZUH_GROUP_TO_EVENT.items():
            if any(needle in g for g in groups):
                add(event_type)

        # ... or where only the description names it (brute force etc.).
        for needle, event_type in WAZUH_DESCRIPTION_TO_EVENT.items():
            if needle in description:
                add(event_type)

        score = level_to_score(level_int)

        # Prefer Wazuh's own MITRE mapping; fall back to CONTEXT_MITRE.
        mitre = self._extract_mitre(rule)
        if not mitre:
            for event_type in derived:
                if event_type in CONTEXT_MITRE:
                    attack = CONTEXT_MITRE[event_type]
                    if attack not in mitre:
                        mitre.append(attack)

        return {
            "score": score,
            "level": level_int,
            "derived_events": derived,
            "mitre": mitre,
            "description": rule.get("description", ""),
            "rule_id": rule.get("id", ""),
        }

    def _extract_mitre(self, rule):
        """
        Wazuh embeds MITRE as rule.mitre = {"id": [...], "technique":
        [...], "tactic": [...]}. Pair ids with technique names when both
        are present.
        """

        mitre_block = rule.get("mitre") or {}
        ids = mitre_block.get("id") or []
        names = mitre_block.get("technique") or []

        result = []
        for i, technique_id in enumerate(ids):
            name = names[i] if i < len(names) else technique_id
            attack = {"id": technique_id, "name": name}
            if attack not in result:
                result.append(attack)

        return result
