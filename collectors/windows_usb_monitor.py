import getpass
import time
import wmi

from collectors.parsers.usb_parser import USBParser
from core.database import insert_event


class WindowsUSBMonitor:

    def __init__(self):

        self.connection = wmi.WMI()

        self.parser = USBParser()

        self.username = getpass.getuser()

    def start(self, duration_seconds=None):
        """
        Watch for USB disk insert/remove events.

        duration_seconds:
            None -> run indefinitely (standalone monitoring mode).
            N    -> poll for approximately N seconds then return, so the
                    one-shot collector run does not block forever.
        """

        print("USB Monitor Started")

        insert_watcher = self.connection.watch_for(
            notification_type="Creation",
            wmi_class="Win32_DiskDrive"
        )

        remove_watcher = self.connection.watch_for(
            notification_type="Deletion",
            wmi_class="Win32_DiskDrive"
        )

        deadline = (
            None
            if duration_seconds is None
            else time.time() + duration_seconds
        )

        while True:

            if deadline is not None and time.time() >= deadline:
                print("USB Monitor Finished")
                return

            try:

                disk = insert_watcher(timeout_ms=1000)

                if disk.InterfaceType == "USB":

                    event = self.parser.parse(
                        disk,
                        self.username,
                        "USB_INSERT"
                    )

                    if event:

                        insert_event(event)

                        print("USB INSERT SAVED")

            except Exception:
                pass


            try:

                disk = remove_watcher(timeout_ms=1000)

                if disk.InterfaceType == "USB":

                    event = self.parser.parse(
                        disk,
                        self.username,
                        "USB_REMOVE"
                    )

                    if event:

                        insert_event(event)

                        print("USB REMOVE SAVED")

            except Exception:
                pass

if __name__ == "__main__":

    monitor = WindowsUSBMonitor()

    monitor.start()