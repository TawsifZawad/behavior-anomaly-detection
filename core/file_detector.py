import os

from specs.process_rules import (
    DROP_PATH_MARKERS,
    DROPPED_FILE_EXTENSIONS,
    DECOY_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
)
from specs.mitre_rules import CONTEXT_MITRE


class FileDetector:
    """
    Context-aware file-creation classifier.

    Given the path of a file that was just created (Sysmon Event ID 11,
    or a write-access Security 4663) and optionally the process that
    created it, decide whether it is a *suspicious download*: an
    executable / script / container file dropped into a download, temp,
    desktop or removable location.

    Mirrors the philosophy of ProcessDetector: the mere creation of a
    file is never suspicious — only its type together with where it
    landed is. Returns the derived event types the FeatureExtractor
    understands (SUSPICIOUS_DOWNLOAD, DOUBLE_EXTENSION), or None.
    """

    def _extension(self, filename):
        parts = filename.lower().rsplit(".", 1)
        return parts[1] if len(parts) == 2 else ""

    def has_double_extension(self, filename):
        parts = filename.lower().split(".")
        if len(parts) < 3:
            return False
        return (
            parts[-1] in EXECUTABLE_EXTENSIONS
            and parts[-2] in DECOY_EXTENSIONS
        )

    def analyze(self, target_filename, creating_process=None):

        path = (target_filename or "").lower()

        if not path:
            return None

        name = os.path.basename(path)
        extension = self._extension(name)

        in_drop_dir = any(marker in path for marker in DROP_PATH_MARKERS)

        score = 0
        derived_events = []
        mitre = []

        def add_event(event_type):
            if event_type not in derived_events:
                derived_events.append(event_type)

        def add_context_mitre(event_type):
            if event_type in CONTEXT_MITRE:
                attack = CONTEXT_MITRE[event_type]
                if attack not in mitre:
                    mitre.append(attack)

        # ---- suspicious download: risky type in a drop location -----
        if in_drop_dir and extension in DROPPED_FILE_EXTENSIONS:

            score += 30
            add_event("SUSPICIOUS_DOWNLOAD")
            add_context_mitre("SUSPICIOUS_DOWNLOAD")

        # ---- double-extension masquerading on the dropped file ------
        if self.has_double_extension(name):

            score += 50
            add_event("DOUBLE_EXTENSION")
            add_context_mitre("DOUBLE_EXTENSION")

        if not derived_events:
            return None

        return {
            "score": score,
            "derived_events": derived_events,
            "mitre": mitre,
            "target": name,
            "creating_process": os.path.basename(
                (creating_process or "").lower()
            ),
        }
