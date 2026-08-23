import os
import json

from collectors.base_collector import BaseCollector
from core.event import Event
from core.wazuh_detector import WazuhDetector
from core.database import create_tables, insert_event
from config.settings import WAZUH_ALERTS_FILE


class WazuhCollector(BaseCollector):
    """
    SIEM-plane collector.

    Reads Wazuh's alerts.json (JSON-per-line) incrementally and turns
    each alert into normalized Event objects via WazuhDetector. These
    land in the same events table as our own host telemetry and the
    Suricata network plane, so a single per-user feature vector spans
    host + SIEM + network.

    This positions the system as an ML / correlation analytics layer on
    top of Wazuh: Wazuh's rule engine supplies known-pattern verdicts,
    which our Isolation Forest + correlation engine fuse with anomaly
    detection and cross-plane context.

    Incremental via a persisted byte offset (log rotation resets it).
    Runs standalone (`python -m collectors.wazuh_collector`) or is
    invoked from the main pipeline.
    """

    OFFSET_FILE = "database/wazuh_last_offset.txt"

    def __init__(self, alerts_path=WAZUH_ALERTS_FILE):

        create_tables()

        super().__init__("Wazuh")

        self.alerts_path = alerts_path
        self.detector = WazuhDetector()

    # ------------------------------------------------------------------
    # Incremental offset helpers
    # ------------------------------------------------------------------

    def read_offset(self):
        if not os.path.exists(self.OFFSET_FILE):
            return 0
        with open(self.OFFSET_FILE, "r") as f:
            value = f.read().strip()
        return int(value) if value else 0

    def write_offset(self, offset):
        os.makedirs(os.path.dirname(self.OFFSET_FILE), exist_ok=True)
        with open(self.OFFSET_FILE, "w") as f:
            f.write(str(offset))

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------

    def collect(self, username=None, reset=False):
        """
        username: attribute alerts to this user so they aggregate with
        the host session under investigation. When omitted, the alert's
        own dstuser / srcuser (or the agent name) is used.

        reset: read the whole file from the start and do not persist the
        offset. Used for reproducible replay of a fixed sample
        alerts.json; live monitoring leaves it False.
        """

        self.start()

        if not os.path.exists(self.alerts_path):
            self.warning(
                f"{self.alerts_path} not found; skipping SIEM plane."
            )
            self.stop()
            return []

        offset = 0 if reset else self.read_offset()
        size = os.path.getsize(self.alerts_path)

        if offset > size:  # rotated / truncated
            offset = 0

        saved = 0
        emitted = 0

        with open(self.alerts_path, "r", errors="ignore") as f:

            f.seek(offset)

            for line in f:

                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                events = self._map_record(record, username)

                for event in events:
                    if insert_event(event):
                        saved += 1
                    emitted += 1

            new_offset = f.tell()

        if not reset:
            self.write_offset(new_offset)

        self.info(
            f"alerts.json -> {emitted} SIEM events "
            f"({saved} new) from {self.alerts_path}."
        )

        self.stop()
        return []

    def _map_record(self, record, username):

        result = self.detector.analyze(record)

        if not result:
            return []

        timestamp = record.get("timestamp") or ""
        if timestamp and "+" in timestamp:
            timestamp = timestamp.split("+")[0]

        data = record.get("data", {}) or {}
        agent = record.get("agent", {}) or {}

        # Attribution preference: explicit arg -> targeted user ->
        # source user -> agent name -> "wazuh".
        user = (
            username
            or data.get("dstuser")
            or data.get("srcuser")
            or agent.get("name")
            or "wazuh"
        )

        src_ip = data.get("srcip", "-")
        rule_id = result.get("rule_id", "")

        events = []

        for event_type in result["derived_events"]:

            record_id = f"wazuh-{rule_id}-{record.get('id', timestamp)}-{event_type}"

            events.append(Event(
                timestamp=timestamp,
                username=user,
                os="SIEM",
                event_type=event_type,
                source="Wazuh",
                ip=str(src_ip),
                details=(
                    f"level={result['level']} | "
                    f"rule={rule_id} | "
                    f"{result.get('description', '')}"
                ),
                event_record_id=record_id,
            ))

        return events


if __name__ == "__main__":
    WazuhCollector().collect()
