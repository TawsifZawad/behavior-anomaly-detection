import os
from datetime import datetime
import xml.etree.ElementTree as ET

import win32evtlog

from collectors.base_collector import BaseCollector
from collectors.filters.windows_filter import WindowsFilter
from collectors.parsers.login_parser import LoginParser
from collectors.parsers.process_parser import ProcessParser
from collectors.parsers.file_parser import FileParser
from collectors.parsers.usb_parser import USBParser

from core.database import create_tables, insert_event


class WindowsCollector(BaseCollector):

    def __init__(self):

        create_tables()

        super().__init__("Windows")

        self.login_parser = LoginParser()
        self.process_parser = ProcessParser()
        self.file_parser = FileParser()
        self.usb_parser = USBParser()

        self.filter = WindowsFilter()

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

            process_name = os.path.basename(
                event_object.details.split("|")[0].strip()
            ).lower()

            if process_name in system_processes:
                continue

            saved = insert_event(event_object)

            if saved:
                saved_count += 1

        print(
            f"Process Summary -> "
            f"Saved: {saved_count}, "
            f"Skipped: {skipped_count}"
        )

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

        print(
            f"File Summary -> "
            f"Saved: {saved_count}, "
            f"Skipped: {skipped_count}"
        )

    ####################################################################
    # USB Events
    ####################################################################

    def collect_usb(self):

        print("Collecting USB events...")

        saved_count = 0
        skipped_count = 0

        query = "*"

        events = self.query_events(
            query=query,
            limit=20,
            log_name="Microsoft-Windows-DriverFrameworks-UserMode/Operational"
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

            event_object = self.usb_parser.parse(xml)

            saved = insert_event(event_object)

            if saved:
                saved_count += 1

        print(
            f"USB Summary -> "
            f"Saved: {saved_count}, "
            f"Skipped: {skipped_count}"
        )

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

        self.collect_logins()
        self.collect_processes()
        self.collect_file_access()
        self.collect_usb()

        if self.latest_record_id > self.last_record_id:
            self.write_last_record_id(self.latest_record_id)

        self.stop()

        return []


if __name__ == "__main__":

    collector = WindowsCollector()

    collector.collect()