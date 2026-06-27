from datetime import datetime

from collectors.base_collector import BaseCollector
from core.database import insert_event
from core.event import Event


class WindowsCollector(BaseCollector):

    def __init__(self):
        super().__init__("Windows")

    def collect(self):

        self.start()

        event = Event(
            timestamp=str(datetime.now()),
            username="test_user",
            os="Windows",
            event_type="LOGIN_SUCCESS",
            source="Security",
            ip="127.0.0.1",
            details="This is a test event"
        )

        insert_event(event)

        self.stop()

        return []