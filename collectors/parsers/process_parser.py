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

            data[item.attrib.get("Name")] = item.text

        timestamp = root.find(
            ".//e:TimeCreated",
            namespace
        ).attrib["SystemTime"]

        event_record_id = root.find(
            ".//e:EventRecordID",
            namespace
        ).text

        process_name = data.get(
            "NewProcessName",
            ""
        )

        command_line = data.get(
            "CommandLine",
            ""
        )

        # Security 4688 reports the creator process as ParentProcessName
        # (full image path). Needed for parent-child context detection
        # (e.g. winword.exe spawning powershell.exe).
        parent_process = data.get(
            "ParentProcessName",
            ""
        ) or ""

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

        details = f"{process_name} | {command_line}"

        if parent_process:
            details += f" | Parent={parent_process}"

        return Event(
            timestamp=timestamp,
            username=username,
            os="Windows",
            event_type="PROCESS_START",
            source="Security",
            ip="-",
            details=details,
            event_record_id=event_record_id
        )