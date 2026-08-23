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

        # ----------------------------
        # System fields
        # ----------------------------

        timestamp = root.find(
            ".//e:TimeCreated",
            namespace
        ).attrib["SystemTime"]

        event_record_id = root.find(
            ".//e:EventRecordID",
            namespace
        ).text

        event_id = root.find(
            ".//e:EventID",
            namespace
        ).text

        logon_type = data.get("LogonType", "")

        # ----------------------------
        # Event Type
        # ----------------------------

        if event_id == "4624":
            event_type = "LOGIN_SUCCESS"

        elif event_id == "4625":
            event_type = "LOGIN_FAILED"

        else:
            event_type = "LOGIN"

        event = Event(
            timestamp=timestamp,
            username=data.get("TargetUserName", "Unknown"),
            os="Windows",
            event_type=event_type,
            source="Security",
            ip=data.get("IpAddress", "-"),
            details=str(data),
            event_record_id=event_record_id
        )

        return event, logon_type