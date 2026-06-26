from dataclasses import dataclass

@dataclass
class Event:

    timestamp: str

    username: str

    os: str

    event_type: str

    source: str

    ip: str = ""

    details: str = ""