import os
import json
import platform
import subprocess

from collectors.base_collector import BaseCollector
from collectors.parsers.mac_parser import MacParser
from core.event import Event
from core.process_detector import ProcessDetector
from core.database import create_tables, insert_event
from config.settings import MACOS_EVENTS_FILE


class MacCollector(BaseCollector):
    """
    macOS host collector.

    Two acquisition paths, same normalized output:

      * live  — on macOS, best-effort `log show` over recent process
                exec / login events (Endpoint Security via `eslogger` is
                used when available). Skipped gracefully off-macOS or when
                the command is unavailable.
      * file  — a JSON-per-line export (MACOS_EVENTS_FILE) for
                reproducible demo / verification, read incrementally with
                a persisted offset (like the Suricata / Wazuh collectors).

    Every process record is run through the (cross-platform)
    ProcessDetector, so the existing macOS rules — osascript shell,
    launchctl / LaunchAgents persistence, /Volumes USB execution, sudo /
    chmod +s escalation — produce the same derived events and MITRE
    techniques as on Windows and Linux.
    """

    OFFSET_FILE = "database/macos_last_offset.txt"

    def __init__(self, events_path=MACOS_EVENTS_FILE):

        create_tables()

        super().__init__("macOS")

        self.events_path = events_path
        self.parser = MacParser()
        self.process_detector = ProcessDetector()

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
    # Derived (context-aware) events
    # ------------------------------------------------------------------

    def emit_derived_events(self, base_event):

        details = base_event.details
        parent = ""
        if " | Parent=" in details:
            details, parent = details.rsplit(" | Parent=", 1)

        parts = details.split("|", 1)
        image = parts[0].strip()
        command = parts[1].strip() if len(parts) > 1 else ""

        result = self.process_detector.analyze(
            image, command, parent_process=parent
        )

        if not result:
            return

        for event_type in result["derived_events"]:
            insert_event(Event(
                timestamp=base_event.timestamp,
                username=base_event.username,
                os="macOS",
                event_type=event_type,
                source="ProcessDetector",
                ip="-",
                details=(
                    f"{os.path.basename(image)} | "
                    f"score={result['score']} | {command}"
                ),
                event_record_id=f"{base_event.event_record_id}-{event_type}",
            ))

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------

    def collect(self, reset=False):

        self.start()

        if platform.system() == "Darwin" and not os.path.exists(
            self.events_path
        ):
            self._collect_live()
        else:
            self._collect_file(reset=reset)

        self.stop()
        return []

    def _collect_file(self, reset=False):

        if not os.path.exists(self.events_path):
            self.warning(
                f"{self.events_path} not found; no macOS telemetry."
            )
            return

        offset = 0 if reset else self.read_offset()
        size = os.path.getsize(self.events_path)
        if offset > size:
            offset = 0

        saved = 0

        with open(self.events_path, "r", errors="ignore") as f:

            f.seek(offset)

            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event = self.parser.parse(record)
                if event is None:
                    continue

                if insert_event(event):
                    saved += 1

                if event.event_type == "PROCESS_START":
                    self.emit_derived_events(event)

            new_offset = f.tell()

        if not reset:
            self.write_offset(new_offset)

        self.info(f"macOS events -> saved {saved} from {self.events_path}.")

    def _collect_live(self):
        """
        Best-effort live acquisition on macOS. Pulls recent process exec
        records from the unified log. Wrapped defensively: any failure
        (missing command, permissions) degrades to a warning.
        """

        try:
            completed = subprocess.run(
                [
                    "log", "show", "--style", "ndjson",
                    "--last", "5m",
                    "--predicate",
                    "eventMessage CONTAINS 'exec' OR "
                    "process == 'loginwindow'",
                ],
                capture_output=True, text=True, timeout=30,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            self.warning(f"live log show unavailable: {exc}")
            return

        saved = 0
        for line in (completed.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Map a unified-log entry to our record shape.
            record = {
                "timestamp": raw.get("timestamp", ""),
                "event_type": "PROCESS_START",
                "user": raw.get("processImageUUID", "macuser"),
                "image": raw.get("processImagePath", ""),
                "command": raw.get("eventMessage", ""),
            }

            event = self.parser.parse(record)
            if event and insert_event(event):
                saved += 1
                self.emit_derived_events(event)

        self.info(f"macOS live log -> saved {saved} events.")


if __name__ == "__main__":
    MacCollector().collect(reset=True)
