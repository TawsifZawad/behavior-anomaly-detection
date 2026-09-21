import os
import json
from collections import defaultdict
from datetime import datetime

from collectors.base_collector import BaseCollector
from core.event import Event
from core.network_detector import NetworkDetector
from core.database import create_tables, insert_event
from config.settings import SURICATA_EVE_FILE
from specs.mitre_rules import CONTEXT_MITRE
from specs.network_rules import (
    PRIVATE_IP_PREFIXES,
    BEACON_MIN_HITS,
    BEACON_MAX_CV,
    BEACON_MIN_INTERVAL,
)


def _is_private_ip(ip):
    if not ip:
        return True
    return any(str(ip).startswith(p) for p in PRIVATE_IP_PREFIXES)


def _parse_epoch(timestamp):
    """Best-effort epoch seconds from a Suricata ISO timestamp."""
    if not timestamp:
        return None
    ts = timestamp.split("+")[0].split("Z")[0]
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return None


def _detect_beacons(dest_times):
    """
    Given {dest_ip: [epoch, ...]} of outbound connections to external
    hosts, return the destinations whose callbacks are periodic enough to
    look like C2 beaconing: enough hits, and a low coefficient of
    variation (std/mean) of the inter-arrival gaps.
    """
    beacons = []
    for dest, times in dest_times.items():
        if len(times) < BEACON_MIN_HITS:
            continue
        times = sorted(times)
        gaps = [b - a for a, b in zip(times, times[1:])]
        gaps = [g for g in gaps if g >= BEACON_MIN_INTERVAL]
        if len(gaps) < BEACON_MIN_HITS - 1:
            continue
        mean = sum(gaps) / len(gaps)
        if mean <= 0:
            continue
        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        cv = (var ** 0.5) / mean
        if cv <= BEACON_MAX_CV:
            beacons.append({
                "dest": dest,
                "hits": len(times),
                "interval": mean,
                "cv": cv,
            })
    return beacons


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

        # Per-external-destination connection timestamps, accumulated
        # across this read so a beaconing pattern (periodic callbacks)
        # can be judged once the whole batch is seen.
        dest_times = defaultdict(list)

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

                self._accumulate_beacon(record, dest_times)

                events = self._map_record(record, username)

                for event in events:
                    if insert_event(event):
                        saved += 1
                    emitted += 1

            new_offset = f.tell()

        # Behaviour pass: emit one C2_BEACONING event per external
        # destination whose callbacks are periodic enough.
        for event in self._beacon_events(dest_times, username):
            if insert_event(event):
                saved += 1
            emitted += 1

        if not reset:
            self.write_offset(new_offset)

        self.info(
            f"eve.json -> {emitted} network events "
            f"({saved} new) from {self.eve_path}."
        )

        self.stop()
        return []

    def _accumulate_beacon(self, record, dest_times):
        """Record the timestamp of any outbound connection to an external
        host, keyed by destination, for the beaconing pass."""
        if record.get("event_type") not in ("flow", "netflow", "dns"):
            return
        dest = record.get("dest_ip")
        if not dest or _is_private_ip(dest):
            return
        epoch = _parse_epoch(record.get("timestamp"))
        if epoch is not None:
            dest_times[dest].append(epoch)

    def _beacon_events(self, dest_times, username):
        events = []
        for beacon in _detect_beacons(dest_times):

            mitre = []
            if "C2_BEACONING" in CONTEXT_MITRE:
                mitre = [CONTEXT_MITRE["C2_BEACONING"]]

            record_id = f"suricata-beacon-{beacon['dest']}"

            events.append(Event(
                timestamp=datetime.now().isoformat(timespec="seconds"),
                username=username or "network",
                os="Network",
                event_type="C2_BEACONING",
                source="Suricata",
                ip=str(beacon["dest"]),
                details=(
                    f"C2 beaconing: {beacon['hits']} periodic callbacks to "
                    f"{beacon['dest']} every ~{beacon['interval']:.0f}s "
                    f"(jitter cv={beacon['cv']:.2f})"
                ),
                event_record_id=record_id,
            ))
        return events

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
