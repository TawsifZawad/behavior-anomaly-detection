import os

from specs.process_rules import POWERSHELL_SUSPICIOUS_KEYWORDS
from specs.mitre_rules import MITRE_MAPPING


class ProcessDetector:

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

    def analyze(self, process_name, command_line):

        process = os.path.basename(
            process_name
        ).lower()

        command = (command_line or "").lower()

        if process not in (
            "powershell.exe",
            "pwsh.exe"
        ):
            return None

        score = 0

        matched_rules = []

        mitre = []

        for keyword, risk in POWERSHELL_SUSPICIOUS_KEYWORDS.items():

            if keyword in command:

                score += risk

                matched_rules.append(keyword)

                if keyword in MITRE_MAPPING:

                    attack = MITRE_MAPPING[keyword]

                    if attack not in mitre:

                        mitre.append(attack)

        if score == 0:
            return None

        return {

            "score": score,

            "severity": self.get_severity(score),

            "rules": matched_rules,

            "mitre": mitre,

            "command": command

        }