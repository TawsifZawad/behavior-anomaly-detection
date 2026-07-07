from dataclasses import dataclass


@dataclass
class Event:

    def __init__(
        self,
        timestamp,
        username,
        os,
        event_type,
        source,
        ip,
        details,
        event_record_id=None
    ):

        self.timestamp = timestamp
        self.username = username
        self.os = os
        self.event_type = event_type
        self.source = source
        self.ip = ip
        self.details = details
        self.event_record_id = event_record_id