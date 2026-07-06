import xml.etree.ElementTree as ET

from core.event import Event


class FileParser:

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

        file_name = data.get(
            "ObjectName",
            ""
        )

        process_name = data.get(
            "ProcessName",
            ""
        )

        access = data.get(
            "AccessMask",
            ""
        )

        details = (
            f"{file_name} | "
            f"{process_name} | "
            f"{access}"
        )

        return Event(

            timestamp=timestamp,
            username=data.get(
                "SubjectUserName",
                "SYSTEM"
            ),
            os="Windows",
            event_type="FILE_ACCESS",
            source="Security",
            ip="-",
            details=details
        )