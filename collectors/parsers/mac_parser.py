from core.event import Event


class MacParser:
    """
    Normalize one macOS telemetry record into an Event.

    Records are JSON objects (one per line) as produced by an
    Endpoint Security export (`eslogger exec`, `eslogger login`) or a
    `log show --style ndjson` predicate, reduced to the fields we model:

        {"timestamp": "...", "event_type": "PROCESS_START",
         "user": "rahim",
         "image": "/usr/bin/osascript",
         "command": "osascript -e 'do shell script ...'",
         "parent": "/Applications/Mail.app/Contents/MacOS/Mail"}

        {"timestamp": "...", "event_type": "LOGIN_SUCCESS",
         "user": "rahim"}

    For process records the image path + command line + parent are packed
    into `details` in the same "image | command | Parent=..." layout the
    Windows process events use, so the collector can hand them straight to
    the (cross-platform) ProcessDetector.
    """

    def parse(self, record):

        if not isinstance(record, dict):
            return None

        event_type = record.get("event_type")
        timestamp = record.get("timestamp") or ""
        user = record.get("user") or "macuser"

        if event_type in ("LOGIN_SUCCESS", "LOGIN_FAILED", "LOGOUT"):
            return Event(
                timestamp=timestamp,
                username=user,
                os="macOS",
                event_type=event_type,
                source="unified-log",
                ip=record.get("ip", "-"),
                details=record.get("details", event_type),
                event_record_id=record.get("id"),
            )

        if event_type == "PROCESS_START":
            image = record.get("image", "")
            command = record.get("command", "") or image
            parent = record.get("parent", "")

            details = f"{image} | {command}"
            if parent:
                details += f" | Parent={parent}"

            return Event(
                timestamp=timestamp,
                username=user,
                os="macOS",
                event_type="PROCESS_START",
                source="ESF",
                ip="-",
                details=details,
                event_record_id=record.get("id"),
            )

        if event_type == "FILE_ACCESS":
            # Keep the filename in details so the feature extractor can read
            # its extension (file-type variety). A file under a mounted
            # volume other than the boot disk is removable-media activity on
            # macOS (e.g. /Volumes/USBSTICK/payload.pdf).
            path = (record.get("path") or record.get("file")
                    or record.get("details") or "")
            details = path
            if path.startswith("/Volumes/") and not path.startswith(
                "/Volumes/Macintosh HD"
            ):
                details = f"{path} | removable"
            return Event(
                timestamp=timestamp,
                username=user,
                os="macOS",
                event_type="FILE_ACCESS",
                source="ESF",
                ip="-",
                details=details,
                event_record_id=record.get("id"),
            )

        if event_type in ("USB_INSERT", "USB_REMOVE", "USB_EXECUTABLE_RUN"):
            return Event(
                timestamp=timestamp,
                username=user,
                os="macOS",
                event_type=event_type,
                source="ESF",
                ip="-",
                details=record.get("details", event_type),
                event_record_id=record.get("id"),
            )

        return None
