import json

from core.event import Event


def load_sample_events(file_path):

    """
    Load events from a JSON file and convert them
    into Event objects.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    events = []

    for item in data:

        event = Event(
            timestamp=item["timestamp"],
            username=item["username"],
            os=item["os"],
            event_type=item["event_type"],
            source=item["source"],
            ip=item["ip"],
            details=item["details"]
        )

        events.append(event)

    return events