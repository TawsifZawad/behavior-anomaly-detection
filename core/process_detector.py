import os

from specs.process_rules import (
    ALL_RULE_GROUPS,
    TEMP_PATH_MARKERS,
    INTERPRETER_PROCESSES,
    REMOVABLE_MEDIA_MARKERS,
    OFFICE_PARENT_PROCESSES,
    OFFICE_SUSPICIOUS_CHILDREN,
    DECOY_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
)
from specs.mitre_rules import MITRE_MAPPING, CONTEXT_MITRE
from specs.exclusions import is_excluded


class ProcessDetector:
    """
    Context-aware command-line classifier.

    Given a process image path, its command line and optional execution
    context (parent process, active USB drive letters), it:
      * scans every keyword rule group (specs/process_rules.py),
      * checks execution context: run-from-USB, double-extension
        masquerading, office-application parent,
      * sums risk weights and collects matched MITRE techniques,
      * returns the list of derived event types the FeatureExtractor
        understands (e.g. ENCODED_COMMAND, USB_EXECUTABLE_RUN).

    A bare interpreter launch (powershell/cmd/bash) with a clean command
    line is still surfaced as a low-severity POWERSHELL_START — the
    "concern" tier — so that "user opened PowerShell" is noticed without
    being treated as a threat.
    """

    def get_severity(self, score):

        if score >= 100:
            return "CRITICAL"

        if score >= 70:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        if score > 0:
            return "LOW"

        return None

    def has_double_extension(self, filename):
        """
        invoice.pdf.exe -> True; setup.exe -> False.
        """

        parts = filename.lower().split(".")

        if len(parts) < 3:
            return False

        return (
            parts[-1] in EXECUTABLE_EXTENSIONS
            and parts[-2] in DECOY_EXTENSIONS
        )

    def analyze(
        self,
        process_name,
        command_line,
        parent_process=None,
        usb_drives=None,
    ):
        """
        usb_drives: optional set of active removable drive letters in
        lowercase "e:" form (Windows). Linux/macOS removable mounts are
        matched by path prefix and need no extra context.
        """

        # Allowlist: the security tool's own operations and operator-
        # trusted commands are suppressed before any classification, so
        # the monitor never alerts on itself or on known-good activity.
        if is_excluded(process_name, command_line):
            return None

        process = os.path.basename(process_name or "").lower()
        parent = os.path.basename(parent_process or "").lower()

        command = (command_line or "").lower()
        path = (process_name or "").lower()

        # Scan against the full command line (includes the image path in
        # most collectors) plus the image path itself, so path-only
        # markers still match.
        haystack = path + " " + command

        score = 0
        matched_rules = []
        mitre = []
        derived_events = []

        def add_event(event_type):
            if event_type not in derived_events:
                derived_events.append(event_type)

        def add_mitre(keyword):
            if keyword in MITRE_MAPPING:
                attack = MITRE_MAPPING[keyword]
                if attack not in mitre:
                    mitre.append(attack)

        def add_context_mitre(event_type):
            if event_type in CONTEXT_MITRE:
                attack = CONTEXT_MITRE[event_type]
                if attack not in mitre:
                    mitre.append(attack)

        # ---- keyword rule groups -----------------------------------
        for rule_group in ALL_RULE_GROUPS:

            for keyword, (risk, event_type) in rule_group.items():

                if keyword in haystack:

                    score += risk
                    matched_rules.append(keyword)
                    add_event(event_type)
                    add_mitre(keyword)

        # ---- execution-from-temp path heuristic --------------------
        for marker in TEMP_PATH_MARKERS:

            if marker in path:

                score += 30
                matched_rules.append(f"path:{marker}")
                add_event("EXECUTION_FROM_TEMP")

                # download dir + a network/download signal already seen
                if "\\downloads\\" == marker or "download" in marker:
                    if "INTERNET_DOWNLOAD" in derived_events:
                        add_event("DOWNLOAD_EXECUTE")

                break

        # ---- execution from removable media ------------------------
        # Windows: image path starts with an active USB drive letter
        # supplied by the collector. Linux/macOS: image path lives under
        # a removable mount point.
        drive = path[:2] if len(path) >= 2 and path[1] == ":" else None

        usb_hit = bool(
            usb_drives and drive and drive in usb_drives
        ) or any(
            path.startswith(marker) for marker in REMOVABLE_MEDIA_MARKERS
        )

        if usb_hit and process:

            score += 40
            matched_rules.append(f"usb:{drive or path}")
            add_event("USB_EXECUTABLE_RUN")
            add_context_mitre("USB_EXECUTABLE_RUN")

        # ---- double-extension masquerading -------------------------
        if self.has_double_extension(process):

            score += 50
            matched_rules.append(f"double_extension:{process}")
            add_event("DOUBLE_EXTENSION")
            add_context_mitre("DOUBLE_EXTENSION")

        # ---- parent-child context (phishing macro chain) ------------
        if (
            parent in OFFICE_PARENT_PROCESSES
            and process in OFFICE_SUSPICIOUS_CHILDREN
        ):

            score += 60
            matched_rules.append(f"parent:{parent}->{process}")
            add_event("OFFICE_SPAWNED_SHELL")
            add_context_mitre("OFFICE_SPAWNED_SHELL")

        # ---- interpreter "concern" tier ----------------------------
        # A bare interpreter launch is worth noticing even with no
        # suspicious keyword. Emit POWERSHELL_START (the generic
        # "script interpreter started" signal the extractor tracks).
        if process in INTERPRETER_PROCESSES:

            if process in ("powershell.exe", "pwsh.exe"):
                add_event("POWERSHELL_START")
                if score == 0:
                    score = 10  # concern, not threat

        if score == 0 and not derived_events:
            return None

        return {
            "score": score,
            "severity": self.get_severity(score),
            "rules": matched_rules,
            "mitre": mitre,
            "derived_events": derived_events,
            "command": command,
        }
