import xml.etree.ElementTree as ET

from core.event import Event


class LoginParser:

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

        logon_type = data.get("LogonType", "")

        event = Event(
            timestamp=timestamp,
            username=data.get("TargetUserName", "Unknown"),
            os="Windows",
            event_type="LOGIN_SUCCESS",
            source="Security",
            ip=data.get("IpAddress", "-"),
            details=str(data)
        )

        return event, logon_type