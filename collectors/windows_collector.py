import os
import ctypes
import string
from datetime import datetime
import xml.etree.ElementTree as ET

import win32evtlog

from collectors.windows_usb_monitor import WindowsUSBMonitor
from collectors.base_collector import BaseCollector
from collectors.parsers.login_parser import LoginParser
from collectors.parsers.process_parser import ProcessParser
from collectors.parsers.file_parser import FileParser
from collectors.parsers.usb_parser import USBParser

from core.database import (
    create_tables,
    insert_event,
    get_usb_drive_letters,
)
from core.event import Event
from core.process_detector import ProcessDetector
from core.file_detector import FileDetector
from core.signature_checker import check_signature
from specs.process_rules import SIGNATURE_CHECK_TRIGGERS

DRIVE_REMOVABLE = 2


def _is_access_denied(exc):
    """True if an exception looks like a Windows access-denied (5) error."""
    text = str(exc).lower()
    return (
        getattr(exc, "winerror", None) == 5
        or "access is denied" in text
        or "denied" in text
    )


class WindowsCollector(BaseCollector):

    def __init__(self):

        create_tables()

        super().__init__("Windows")

        self.login_parser = LoginParser()
        self.process_parser = ProcessParser()
        self.file_parser = FileParser()
        self.process_detector = ProcessDetector()
        self.file_detector = FileDetector()
        self.usb_monitor = WindowsUSBMonitor()

        self.last_collect_time = None
        self.latest_event_time = None

    ####################################################################
    # Incremental Collection Helpers
    ####################################################################

    def read_last_record_id(self):

        path = "database/last_record_id.txt"

        if not os.path.exists(path):
            return 0

        with open(path, "r") as f:
            value = f.read().strip()

        if value == "":
            return 0

        return int(value)


    def write_last_record_id(self, record_id):

        path = "database/last_record_id.txt"

        with open(path, "w") as f:
            f.write(str(record_id))

    ####################################################################
    # Removable Media Context
    ####################################################################

    def get_usb_drives(self):
        """
        Active removable drive letters right now (via GetDriveTypeW)
        plus letters recorded by past USB_INSERT events, lowercase
        ("e:"). Passed to ProcessDetector so an execution path on one
        of these drives becomes USB_EXECUTABLE_RUN.
        """

        drives = set()

        try:

            bitmask = ctypes.windll.kernel32.GetLogicalDrives()

            for index, letter in enumerate(string.ascii_uppercase):

                if not bitmask & (1 << index):
                    continue

                drive_type = ctypes.windll.kernel32.GetDriveTypeW(
                    f"{letter}:\\"
                )

                if drive_type == DRIVE_REMOVABLE:
                    drives.add(f"{letter.lower()}:")

        except Exception:
            pass

        drives |= get_usb_drive_letters()

        return drives

    ####################################################################
    # Event Time
    ####################################################################

    def get_event_time(self, xml):

        root = ET.fromstring(xml)

        namespace = {
            "e": "http://schemas.microsoft.com/win/2004/08/events/event"
        }

        timestamp = root.find(
            ".//e:TimeCreated",
            namespace
        ).attrib["SystemTime"]

        timestamp = timestamp.replace("Z", "")

        if "." in timestamp:

            left, right = timestamp.split(".", 1)

            digits = ""

            for c in right:

                if c.isdigit():
                    digits += c
                else:
                    break

            digits = digits[:6]

            timestamp = left + "." + digits

        return datetime.fromisoformat(timestamp)
    
    def get_record_id(self, xml):

        import xml.etree.ElementTree as ET

        root = ET.fromstring(xml)

        namespace = {
            "e": "http://schemas.microsoft.com/win/2004/08/events/event"
        }

        record_id = root.find(
            ".//e:EventRecordID",
            namespace
        )

        return int(record_id.text)

    ####################################################################
    # Login Events
    ####################################################################

    def collect_logins(self):

        print("Collecting login events...")

        saved_count = 0
        skipped_count = 0

        query = "*[System[(EventID=4624 or EventID=4625)]]"

        events = self.query_events(
            query=query,
            limit=100
        )

        print(f"Events Found: {len(events)}")

        for event in events:

            xml = win32evtlog.EvtRender(
                event,
                win32evtlog.EvtRenderEventXml
            )

            record_id = self.get_record_id(xml)

            if record_id > self.latest_record_id:
                self.latest_record_id = record_id

            if record_id <= self.last_record_id:
                skipped_count += 1
                continue

            event_object, logon_type = self.login_parser.parse(xml)

            if logon_type == "5":
                continue

            saved = insert_event(event_object)

            if saved:
                saved_count += 1

        print(
            f"Login Summary -> "
            f"Saved: {saved_count}, "
            f"Skipped: {skipped_count}"
        )

        ####################################################################
    # Process Events
    ####################################################################

    def collect_processes(self):

        print("Collecting process events...")

        saved_count = 0
        skipped_count = 0

        query = "*[System[(EventID=4688)]]"

        events = self.query_events(
            query=query,
            limit=500
        )

        print(f"Events Found: {len(events)}")

        # Resolved once per collection run: removable drives currently
        # attached + drive letters recorded by USB_INSERT events.
        usb_drives = self.get_usb_drives()

        if usb_drives:
            print(f"USB drives in scope: {sorted(usb_drives)}")

        system_processes = {
            "lsass.exe",
            "smss.exe",
            "csrss.exe",
            "services.exe",
            "wininit.exe",
            "winlogon.exe",
            "autochk.exe",
            "svchost.exe",
            "taskhostw.exe",
            "runtimebroker.exe",
            "backgroundtaskhost.exe",
            "dllhost.exe",
            "conhost.exe",
            "searchhost.exe",
            "searchindexer.exe",
            "fontdrvhost.exe",
            "sihost.exe",
            "ctfmon.exe",
            "registry"
        }

        for event in events:

            xml = win32evtlog.EvtRender(
                event,
                win32evtlog.EvtRenderEventXml
            )

            record_id = self.get_record_id(xml)

            if record_id > self.latest_record_id:
                self.latest_record_id = record_id

            if record_id <= self.last_record_id:
                skipped_count += 1
                continue

            event_object = self.process_parser.parse(xml)

            # details = "image | command_line[ | Parent=path]"
            details = event_object.details
            parent_process = ""

            if " | Parent=" in details:
                details, parent_process = details.rsplit(" | Parent=", 1)

            parts = details.split("|", 1)
            image_path = parts[0].strip()
            command_line = parts[1].strip() if len(parts) > 1 else ""

            process_name = os.path.basename(image_path).lower()

            if process_name in system_processes:
                continue

            saved = insert_event(event_object)

            if saved:
                saved_count += 1

            # Context-aware classification: turn the command line and
            # execution context (parent process, USB drives) into
            # derived behavioral events (ENCODED_COMMAND, USB_
            # EXECUTABLE_RUN, ...) that the FeatureExtractor understands.
            self.emit_derived_events(
                event_object,
                image_path,
                command_line,
                parent_process=parent_process,
                usb_drives=usb_drives
            )

        print(
            f"Process Summary -> "
            f"Saved: {saved_count}, "
            f"Skipped: {skipped_count}"
        )

    ####################################################################
    # Derived (context-aware) events
    ####################################################################

    def emit_derived_events(
        self,
        base_event,
        image_path,
        command_line,
        parent_process="",
        usb_drives=None
    ):
        """
        Classify a process command line and insert one extra normalized
        event per derived behavior. Each derived event reuses the base
        4688 record id with a per-type suffix so the UNIQUE constraint on
        event_record_id is not violated.
        """

        result = self.process_detector.analyze(
            image_path,
            command_line,
            parent_process=parent_process,
            usb_drives=usb_drives
        )

        if not result:
            return

        derived_events = list(result["derived_events"])

        # Signature check only when the execution already looks
        # suspicious (temp / USB / masquerading name). check_signature
        # returns None when undeterminable — never treated as unsigned.
        if SIGNATURE_CHECK_TRIGGERS & set(derived_events):

            if check_signature(image_path) is False:

                derived_events.append("UNSIGNED_BINARY")
                result["score"] += 20

        base_id = base_event.event_record_id

        for event_type in derived_events:

            derived_id = f"{base_id}-{event_type}"

            derived_event = Event(
                timestamp=base_event.timestamp,
                username=base_event.username,
                os="Windows",
                event_type=event_type,
                source="ProcessDetector",
                ip="-",
                details=(
                    f"{os.path.basename(image_path)} | "
                    f"score={result['score']} | "
                    f"{command_line}"
                ),
                event_record_id=derived_id
            )

            insert_event(derived_event)

    ####################################################################
    # File Events
    ####################################################################

    def collect_file_access(self):

        print("Collecting file access events...")

        saved_count = 0
        skipped_count = 0

        query = "*[System[(EventID=4663)]]"

        events = self.query_events(
            query=query,
            limit=100
        )

        print(f"Events Found: {len(events)}")

        for event in events:

            xml = win32evtlog.EvtRender(
                event,
                win32evtlog.EvtRenderEventXml
            )

            record_id = self.get_record_id(xml)

            if record_id > self.latest_record_id:
                self.latest_record_id = record_id

            if record_id <= self.last_record_id:
                skipped_count += 1
                continue

            event_object = self.file_parser.parse(xml)

            saved = insert_event(event_object)

            if saved:
                saved_count += 1

            # details = "objectname | process | accessmask"
            object_name = event_object.details.split("|", 1)[0].strip()

            self.emit_file_events(
                object_name,
                creating_process="",
                base_id=event_object.event_record_id,
                timestamp=event_object.timestamp,
                username=event_object.username,
            )

        print(
            f"File Summary -> "
            f"Saved: {saved_count}, "
            f"Skipped: {skipped_count}"
        )

    ####################################################################
    # File Creation (Sysmon Event ID 11)
    ####################################################################

    def collect_file_creation(self):
        """
        Sysmon Event ID 11 (FileCreate) is the honest signal that a file
        landed on disk. When the created file is an executable / script /
        container dropped into a download, temp, desktop or removable
        location, emit SUSPICIOUS_DOWNLOAD. Silently skipped on hosts
        without Sysmon installed.
        """

        try:
            events = self.query_events(
                query="*[System[(EventID=11)]]",
                limit=200,
                log_name="Microsoft-Windows-Sysmon/Operational",
            )
        except Exception:
            print("Sysmon channel not available; skipping file-creation.")
            return

        print(f"Sysmon FileCreate events found: {len(events)}")

        namespace = {
            "e": "http://schemas.microsoft.com/win/2004/08/events/event"
        }

        saved = 0

        for event in events:

            xml = win32evtlog.EvtRender(
                event, win32evtlog.EvtRenderEventXml
            )

            root = ET.fromstring(xml)

            data = {}
            for item in root.findall(".//e:EventData/e:Data", namespace):
                data[item.attrib.get("Name")] = item.text

            target = data.get("TargetFilename", "")
            image = data.get("Image", "")
            record_id = self.get_record_id(xml)

            if self.emit_file_events(
                target,
                creating_process=image,
                base_id=f"sysmon11-{record_id}",
                timestamp=data.get("UtcTime")
                or datetime.now().isoformat(),
                username=data.get("User", "SYSTEM"),
            ):
                saved += 1

        print(f"File Creation Summary -> Suspicious drops: {saved}")

    def emit_file_events(
        self,
        target_filename,
        creating_process,
        base_id,
        timestamp,
        username,
    ):
        """
        Classify a created/accessed file path and insert one derived
        event per detected behavior (SUSPICIOUS_DOWNLOAD, DOUBLE_
        EXTENSION). Returns True if anything was emitted.
        """

        result = self.file_detector.analyze(
            target_filename, creating_process
        )

        if not result:
            return False

        for event_type in result["derived_events"]:

            insert_event(Event(
                timestamp=timestamp,
                username=username or "SYSTEM",
                os="Windows",
                event_type=event_type,
                source="FileDetector",
                ip="-",
                details=(
                    f"{result['target']} | "
                    f"score={result['score']} | "
                    f"proc={result['creating_process']}"
                ),
                event_record_id=f"{base_id}-{event_type}",
            ))

        return True

    ####################################################################
    # Query Events
    ####################################################################

    def query_events(
        self,
        query,
        limit=100,
        log_name="Security"
    ):

        handle = win32evtlog.EvtQuery(
            log_name,
            win32evtlog.EvtQueryReverseDirection,
            query
        )

        return win32evtlog.EvtNext(
            handle,
            limit
        )

    ####################################################################
    # Main Collector
    ####################################################################

    def collect(self):

        self.start()

        self.last_record_id = self.read_last_record_id()
        self.latest_record_id = self.last_record_id

        # Reading the Security event log needs Administrator rights.
        # Wrap each phase so an access-denied (or any) failure logs a
        # clear hint and the run continues instead of crashing — partial
        # telemetry plus the network / SIEM planes is still useful.
        denied = False

        for label, phase in (
            ("login events", self.collect_logins),
            ("process events", self.collect_processes),
            ("file access events", self.collect_file_access),
            ("file creation events", self.collect_file_creation),
        ):
            try:
                phase()
            except Exception as exc:  # noqa: BLE001 - report and continue
                denied = denied or _is_access_denied(exc)
                print(f"  [!] Could not collect {label}: {exc}")

        if denied:
            print(
                "\n  NOTE: reading the Windows Security log requires "
                "Administrator rights.\n"
                "        Right-click bads.exe -> 'Run as administrator' "
                "for full host collection.\n"
            )

        print("Starting USB Monitor...")

        try:
            # Time-boxed so a single collection run cannot block forever.
            self.usb_monitor.start(duration_seconds=5)
        except Exception as exc:  # noqa: BLE001
            print(f"  [!] USB monitor unavailable: {exc}")

        if self.latest_record_id > self.last_record_id:
            self.write_last_record_id(self.latest_record_id)

        self.stop()

        return []


if __name__ == "__main__":

    collector = WindowsCollector()

    collector.collect()