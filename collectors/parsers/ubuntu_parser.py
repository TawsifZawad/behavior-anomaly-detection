import re
import hashlib
from datetime import datetime

from collectors.parsers.base_parser import BaseParser
from core.event import Event


class UbuntuParser(BaseParser):
    """
    Parse a single /var/log/auth.log line into a normalized Event.

    Recognized formats:
        * sshd "Accepted ..."            -> LOGIN_SUCCESS (captures IP)
        * sshd "Failed password ..."     -> LOGIN_FAILED  (captures IP)
        * "session opened for user X"    -> LOGIN_SUCCESS
        * "session closed for user X"    -> LOGOUT
        * "sudo: USER : ... COMMAND=..." -> PROCESS_START (sudo command)

    Returns an Event, or None for lines that do not match.
    Sudo COMMAND lines are returned as PROCESS_START events whose details
    are "binary | full command"; the collector then runs them through the
    ProcessDetector to emit derived (context-aware) events.
    """

    SSH_ACCEPTED = re.compile(
        r"Accepted \S+ for (?:invalid user )?(?P<user>\S+) "
        r"from (?P<ip>\S+)"
    )

    SSH_FAILED = re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) "
        r"from (?P<ip>\S+)"
    )

    SESSION_OPENED = re.compile(
        r"session opened for user (?P<user>[\w.-]+)"
    )

    SESSION_CLOSED = re.compile(
        r"session closed for user (?P<user>[\w.-]+)"
    )

    SUDO_COMMAND = re.compile(
        r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)$"
    )

    def _timestamp(self, line):
        """
        auth.log syslog timestamps have no year (e.g. 'Jan  8 14:23:01').
        Attach the current year and return an ISO string the
        FeatureExtractor can parse with datetime.fromisoformat.
        """
        match = re.match(
            r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
            line
        )

        if not match:
            return datetime.now().isoformat()

        try:
            parsed = datetime.strptime(match.group("ts"), "%b %d %H:%M:%S")
            parsed = parsed.replace(year=datetime.now().year)
            return parsed.isoformat()
        except ValueError:
            return datetime.now().isoformat()

    def _record_id(self, line):
        # Stable id derived from the raw line so re-reading the log does
        # not create duplicates (insert_event dedups on event_record_id).
        digest = hashlib.md5(line.strip().encode("utf-8")).hexdigest()
        return f"ubuntu-{digest}"

    def parse(self, raw_event):

        line = (raw_event or "").rstrip("\n")

        if not line:
            return None

        timestamp = self._timestamp(line)
        record_id = self._record_id(line)

        # ---- SSH accepted -----------------------------------------
        match = self.SSH_ACCEPTED.search(line)
        if match:
            return Event(
                timestamp=timestamp,
                username=match.group("user"),
                os="Ubuntu",
                event_type="LOGIN_SUCCESS",
                source="auth.log",
                ip=match.group("ip"),
                details=line,
                event_record_id=record_id,
            )

        # ---- SSH failed -------------------------------------------
        match = self.SSH_FAILED.search(line)
        if match:
            return Event(
                timestamp=timestamp,
                username=match.group("user"),
                os="Ubuntu",
                event_type="LOGIN_FAILED",
                source="auth.log",
                ip=match.group("ip"),
                details=line,
                event_record_id=record_id,
            )

        # ---- sudo command -----------------------------------------
        match = self.SUDO_COMMAND.search(line)
        if match:
            command = match.group("command").strip()
            binary = command.split()[0] if command else command
            return Event(
                timestamp=timestamp,
                username=match.group("user"),
                os="Ubuntu",
                event_type="PROCESS_START",
                source="auth.log",
                ip="-",
                details=f"{binary} | {command}",
                event_record_id=record_id,
            )

        # ---- session opened ---------------------------------------
        match = self.SESSION_OPENED.search(line)
        if match:
            return Event(
                timestamp=timestamp,
                username=match.group("user"),
                os="Ubuntu",
                event_type="LOGIN_SUCCESS",
                source="auth.log",
                ip="-",
                details=line,
                event_record_id=record_id,
            )

        # ---- session closed ---------------------------------------
        match = self.SESSION_CLOSED.search(line)
        if match:
            return Event(
                timestamp=timestamp,
                username=match.group("user"),
                os="Ubuntu",
                event_type="LOGOUT",
                source="auth.log",
                ip="-",
                details=line,
                event_record_id=record_id,
            )

        return None
