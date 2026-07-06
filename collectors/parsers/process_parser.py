import xml.etree.ElementTree as ET

from core.event import Event


class ProcessParser:

    def parse(self, xml):

        root = ET.fromstring(xml)

        namespace = {
            "e": "http://schemas.microsoft.com/win/2004/08/events/event"
        }

        data = {}

        for item in root.findall(".//e:EventData/e:Data", namespace):

            name = item.attrib.get("Name")
            value = item.text

            data[name] = value

        timestamp = root.find(
            ".//e:TimeCreated",
            namespace
        ).attrib["SystemTime"]

        # Process Name
        process_name = data.get(
            "NewProcessName",
            ""
        )

        # Username
        username = data.get(
            "SubjectUserName", 
            "-"
            
        )

        if username == "-":
            username = data.get(
                "TargetUserName", 
                "-"
            
            )

        if username == "-":
            username = "SYSTEM"

        return Event(
            timestamp=timestamp,
            username=username,
            os="Windows",
            event_type="PROCESS_START",
            source="Security",
            ip="-",
            details=process_name
        )