from datetime import datetime

from core.event import Event


class USBParser:

    def get_drive_letters(self, disk):
        """
        Resolve the logical drive letters (["E:"]) of a Win32_DiskDrive
        via its partition associations. May be empty right after insert
        if the volume has not mounted yet.
        """

        letters = []

        try:

            for partition in disk.associators(
                "Win32_DiskDriveToDiskPartition"
            ):

                for logical in partition.associators(
                    "Win32_LogicalDiskToPartition"
                ):

                    letters.append(logical.DeviceID)

        except Exception:
            pass

        return letters

    def parse(
        self,
        disk,
        username,
        event_type
    ):

        drive_letters = self.get_drive_letters(disk)

        details = (
            f"Manufacturer={getattr(disk,'Manufacturer','Unknown')} | "
            f"Model={disk.Model} | "
            f"Device={disk.DeviceID} | "
            f"Interface={disk.InterfaceType} | "
            f"Drive={','.join(drive_letters) if drive_letters else 'Unknown'}"
        )

        return Event(

            timestamp=datetime.now().isoformat(),

            username=username,

            os="Windows",

            event_type=event_type,

            source="WMI",

            ip="-",

            details=details,

            event_record_id=int(datetime.now().timestamp()*1000)
        )
