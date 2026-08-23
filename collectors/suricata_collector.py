import os
import json

from collectors.base_collector import BaseCollector
from core.event import Event
from core.network_detector import NetworkDetector
from core.database import create_tables, insert_event
from config.settings import SURICATA_EVE_FILE


class SuricataCollector(BaseCollector):
    """
    Network-plane collector.

    Reads Suricata's eve.json (JSON-per-line) incrementally and turns
    modelled records (alerts + large flows) into normalized network
    Event objects via NetworkDetector. These land in the same events
    table as host telemetry, so the FeatureExtractor produces a single
    per-user feature vector spanning both the host and network planes.

    Incremental: a byte offset is persisted so each run only reads new
    lines; a shrunk file (log rotation) resets the offset.

    Runs standalone (`python -m collectors.suricata_collector`) or is
    invoked by an OS collector to add network context to a session.
    """

    OFFSET_FILE = "database/suricata_last_offset.txt"

    def __init__(self, eve_path=SURICATA_EVE_FILE):

        create_tables()

        super().__init__("Suricata")

        self.eve_path = eve_path
        self.detector = NetworkDetector()

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
        username: when supplied, attribute network events to that user so
        they aggregate with the host session under investigation. Suricata
        sees IPs, not OS users, so on a single-user host the caller passes
        the logged-in user; otherwise events are attributed to "network".

        reset: read the whole file from the start and do not persist the
        offset. Used for reproducible replay of a fixed sample eve.json;
        live monitoring leaves it False so each run only reads new lines.
        """

        self.start()

        if not os.path.exists(self.eve_path):
            self.warning(f"{self.eve_path} not found; skipping network plane.")
            self.stop()
            return []

        offset = 0 if reset else self.read_offset()
        size = os.path.getsize(self.eve_path)

        if offset > size:  # rotated / truncated
            offset = 0

        saved = 0
        emitted = 0

        with open(self.eve_path, "r", errors="ignore") as f:

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
            f"eve.json -> {emitted} network events "
            f"({saved} new) from {self.eve_path}."
        )

        self.stop()
        return []

    def _map_record(self, record, username):

        result = self.detector.analyze(record)

        if not result:
            return []

        timestamp = record.get("timestamp") or ""
        # normalize Suricata's "2026-07-12T10:00:00.000000+0000" a bit;
        # the extractor only needs an ISO-parseable prefix.
        if timestamp and "+" in timestamp:
            timestamp = timestamp.split("+")[0]

        flow_id = record.get("flow_id", "")
        src = result.get("src_ip", "-")
        dest = result.get("dest_ip", "-")

        events = []

        for event_type in result["derived_events"]:

            record_id = f"suricata-{flow_id}-{event_type}"

            events.append(Event(
                timestamp=timestamp,
                username=username or "network",
                os="Network",
                event_type=event_type,
                source="Suricata",
                ip=str(src),
                details=(
                    f"{result.get('signature', '')} | "
                    f"score={result['score']} | "
                    f"{src} -> {dest}"
                ),
                event_record_id=record_id,
            ))

        return events


if __name__ == "__main__":
    SuricataCollector().collect()
