from datetime import datetime

import win32evtlog
import xml.etree.ElementTree as ET

from collectors.filters.windows_filter import WindowsFilter
from collectors.parsers.login_parser import LoginParser
from collectors.base_collector import BaseCollector
from core.database import insert_event
from core.event import Event


class WindowsCollector(BaseCollector):

    def __init__(self):

        super().__init__("Windows")

        self.login_parser = LoginParser()

        self.filter = WindowsFilter()

    def collect_logins(self):

        print("Collecting login events...")

        query = "*[System[(EventID=4624 or EventID=4625)]]"

        handle = win32evtlog.EvtQuery(

            "Security",

            win32evtlog.EvtQueryReverseDirection,

            query

        )

        events = win32evtlog.EvtNext(

            handle,

            5

        )

        print(f"Events Found: {len(events)}")
    def collect_processes(self):

        print("Collecting process events...")

    def collect_file_access(self):

        print("Collecting file access events...")
    
    def collect_usb(self):

        print("Collecting USB events...")

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