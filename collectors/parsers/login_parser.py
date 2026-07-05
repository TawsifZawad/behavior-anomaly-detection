from core.event import Event


class LoginParser:

    def parse(
        self,
        timestamp,
        username,
        event_type,
        source="Security",
        ip="-",
        details=""
    ):

        return Event(
            timestamp=timestamp,
            username=username,
            os="Windows",
            event_type=event_type,
            source=source,
            ip=ip,
            details=details
        )