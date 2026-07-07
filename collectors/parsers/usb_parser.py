import xml.etree.ElementTree as ET

from core.event import Event


class USBParser:

    def parse(self, xml):

        root = ET.fromstring(xml)

        namespace = {
            "e": "http://schemas.microsoft.com/win/2004/08/events/event"
        }

        timestamp = root.find(
            ".//e:TimeCreated",
            namespace
        ).attrib["SystemTime"]

        event_record_id = root.find(
            ".//e:EventRecordID",
            namespace
        ).text

        return Event(
            timestamp=timestamp,
            username="SYSTEM",
            os="Windows",
            event_type="USB_EVENT",
            source="DriverFrameworks",
            ip="-",
            details=xml,
            event_record_id=event_record_id
        )