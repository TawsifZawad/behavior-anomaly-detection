import os

import win32evtlog

from collectors.parsers.process_parser import ProcessParser
from collectors.parsers.file_parser import FileParser
from collectors.parsers.usb_parser import USBParser
from collectors.base_collector import BaseCollector
from collectors.filters.windows_filter import WindowsFilter
from collectors.parsers.login_parser import LoginParser
from core.database import insert_event


class WindowsCollector(BaseCollector):

    def __init__(self):

        super().__init__("Windows")

        self.login_parser = LoginParser()

        self.process_parser = ProcessParser()

        self.file_parser = FileParser()

        self.usb_parser = USBParser()

        self.filter = WindowsFilter()

    def collect_logins(self):

        print("Collecting login events...")

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

            event_object, logon_type = self.login_parser.parse(xml)

            if logon_type == "5":
                continue

            insert_event(event_object)

            print(
                f"Saved Login Event: {event_object.username}"
            )

            break

    def collect_processes(self):

        print("Collecting process events...")

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

            event_object = self.process_parser.parse(xml)

            process_name = os.path.basename(
                event_object.details
            ).lower()

            print(f"Process: {process_name}")

            if process_name in system_processes:

                print(f"Skipped: {process_name}")

                continue

            print(f"Saving: {process_name}")

            insert_event(event_object)

            print(
                f"Saved Process Event: {process_name}"
            )

    def collect_file_access(self):

        print("Collecting file access events...")

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

            event_object = self.file_parser.parse(xml)

            insert_event(event_object)

            print(
                f"Saved File Event: {event_object.details}"
            )

            break
    
    def collect_usb(self):

        print("Collecting USB events...")

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

            print("=" * 60)
            print(xml)

            break

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

    def collect(self):

        self.start()

        self.collect_logins()

        self.collect_processes()

        self.collect_file_access()

        self.collect_usb()

        self.stop()

        return []


if __name__ == "__main__":

    collector = WindowsCollector()

    collector.collect()