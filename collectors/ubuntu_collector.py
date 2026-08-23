import os

from collectors.base_collector import BaseCollector
from collectors.parsers.ubuntu_parser import UbuntuParser
from core.event import Event
from core.process_detector import ProcessDetector
from core.file_detector import FileDetector
from core.database import create_tables, insert_event


class UbuntuCollector(BaseCollector):
    """
    Collect security events on Ubuntu/Linux.

    Sources:
        * /var/log/auth.log  — logins, sudo commands (always attempted)
        * /var/log/audit/audit.log — EXECVE process events (if auditd is
          installed; degrades gracefully when absent)

    auth.log is read incrementally: a byte offset is persisted so each
    run only processes new lines. Log rotation is handled by resetting
    the offset when the file has shrunk.
    """

    AUTH_LOG = "/var/log/auth.log"
    AUDIT_LOG = "/var/log/audit/audit.log"
    OFFSET_FILE = "database/ubuntu_last_offset.txt"

    # Paths that represent real user file activity (not system libraries),
    # and the subset that lives on removable media.
    USER_FILE_PREFIXES = ("/home/", "/root/", "/tmp/", "/media/", "/mnt/",
                          "/run/media/")
    REMOVABLE_PREFIXES = ("/media/", "/mnt/", "/run/media/")

    def __init__(self):

        create_tables()

        super().__init__("Ubuntu")

        self.parser = UbuntuParser()
        self.process_detector = ProcessDetector()
        self.file_detector = FileDetector()

    ####################################################################
    # Incremental offset helpers
    ####################################################################

    def read_offset(self):

        if not os.path.exists(self.OFFSET_FILE):
            return 0

        with open(self.OFFSET_FILE, "r") as f:
            value = f.read().strip()

        return int(value) if value else 0

    def write_offset(self, offset):

        os.makedirs(os.path.dirname(self.OFFSET_FILE), exist_ok=True)

        with open(self.OFFSET_FILE, "w") as f:
            f.write(str(offset))

    ####################################################################
    # Derived (context-aware) events
    ####################################################################

    def emit_derived_events(self, base_event):
        """
        Run a PROCESS_START event's command through the ProcessDetector
        and insert one derived event per detected behavior.
        """

        parts = base_event.details.split("|", 1)
        image_path = parts[0].strip()
        command_line = parts[1].strip() if len(parts) > 1 else ""

        result = self.process_detector.analyze(image_path, command_line)

        if not result:
            return

        for event_type in result["derived_events"]:

            derived_id = f"{base_event.event_record_id}-{event_type}"

            insert_event(Event(
                timestamp=base_event.timestamp,
                username=base_event.username,
                os="Ubuntu",
                event_type=event_type,
                source="ProcessDetector",
                ip="-",
                details=(
                    f"{os.path.basename(image_path)} | "
                    f"score={result['score']} | {command_line}"
                ),
                event_record_id=derived_id,
            ))

    ####################################################################
    # auth.log
    ####################################################################

    def collect_auth_log(self):

        if not os.path.exists(self.AUTH_LOG):
            self.warning(f"{self.AUTH_LOG} not found; skipping.")
            return

        offset = self.read_offset()
        size = os.path.getsize(self.AUTH_LOG)

        # Log rotation: file shrank, start from the beginning.
        if offset > size:
            offset = 0

        saved = 0

        with open(self.AUTH_LOG, "r", errors="ignore") as f:

            f.seek(offset)

            for line in f:

                event = self.parser.parse(line)

                if event is None:
                    continue

                inserted = insert_event(event)

                if inserted:
                    saved += 1

                if event.event_type == "PROCESS_START":
                    self.emit_derived_events(event)

            new_offset = f.tell()

        self.write_offset(new_offset)

        self.info(f"auth.log -> saved {saved} new events.")

    ####################################################################
    # auditd (optional)
    ####################################################################

    def collect_audit_log(self):

        if not os.path.exists(self.AUDIT_LOG):
            self.info("auditd log not present; skipping process auditing.")
            return

        saved = 0

        try:
            with open(self.AUDIT_LOG, "r", errors="ignore") as f:
                lines = f.readlines()
        except PermissionError:
            self.warning("No permission to read auditd log; skipping.")
            return

        for line in lines:

            # auditd PATH records report files touched by a syscall.
            # A newly created file (nametype=CREATE) in a drop location
            # is a suspicious download on Linux too.
            if "type=PATH" in line:
                # Every touched user file becomes a FILE_ACCESS event (its
                # extension feeds file-type variety; a removable-mount path
                # feeds removable-media activity). A newly created file also
                # runs through the FileDetector.
                self._emit_file_access(line)
                if "nametype=CREATE" in line:
                    self._emit_file_creation(line)
                continue

            if "type=EXECVE" not in line:
                continue

            command = self._parse_execve(line)

            if not command:
                continue

            binary = command.split()[0] if command else command

            base_event = Event(
                timestamp=self.parser._timestamp(line),
                username="audit",
                os="Ubuntu",
                event_type="PROCESS_START",
                source="auditd",
                ip="-",
                details=f"{binary} | {command}",
                event_record_id=self.parser._record_id(line),
            )

            if insert_event(base_event):
                saved += 1

            self.emit_derived_events(base_event)

        self.info(f"auditd -> saved {saved} process events.")

    @staticmethod
    def _path_name(line):
        """The file path from an auditd PATH record (name="..."), or None."""
        for token in line.split():
            if token.startswith("name="):      # excludes 'nametype='
                return token.partition("=")[2].strip('"')
        return None

    def _emit_file_access(self, line):
        """
        Emit a FILE_ACCESS event for a user-relevant auditd PATH record,
        keeping the filename in details so the extractor can read its
        extension (file-type variety), and flagging it as removable-media
        activity when the path sits on a removable mount. Requires auditd
        file-watch rules for the value to be non-zero.
        """
        name = self._path_name(line)
        if not name or not name.startswith(self.USER_FILE_PREFIXES):
            return

        details = name
        if name.startswith(self.REMOVABLE_PREFIXES):
            details = f"{name} | removable"

        insert_event(Event(
            timestamp=self.parser._timestamp(line),
            username="audit",
            os="Ubuntu",
            event_type="FILE_ACCESS",
            source="auditd",
            ip="-",
            details=details,
            event_record_id=f"{self.parser._record_id(line)}-FA",
        ))

    def _emit_file_creation(self, line):
        """
        Run a created file path (auditd PATH record) through the
        FileDetector and insert a SUSPICIOUS_DOWNLOAD / DOUBLE_EXTENSION
        event when it lands in a drop location with a risky type.
        """

        name = self._path_name(line)

        if not name:
            return

        result = self.file_detector.analyze(name)

        if not result:
            return

        record_id = self.parser._record_id(line)

        for event_type in result["derived_events"]:

            insert_event(Event(
                timestamp=self.parser._timestamp(line),
                username="audit",
                os="Ubuntu",
                event_type=event_type,
                source="FileDetector",
                ip="-",
                details=f"{result['target']} | score={result['score']}",
                event_record_id=f"{record_id}-{event_type}",
            ))

    def _parse_execve(self, line):
        # EXECVE records look like: ... a0="bash" a1="-c" a2="whoami"
        args = []
        for token in line.split():
            if token.startswith("a") and "=" in token:
                key, _, value = token.partition("=")
                if key[1:].isdigit():
                    args.append(value.strip('"'))
        return " ".join(args)

    ####################################################################
    # Main
    ####################################################################

    def collect(self):

        self.start()

        self.collect_auth_log()
        self.collect_audit_log()

        self.stop()

        return []


if __name__ == "__main__":

    collector = UbuntuCollector()
    collector.collect()
