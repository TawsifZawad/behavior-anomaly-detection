class CorrelationEngine:

    def analyze(self, comparison, features):

        """
        Detect attack chains by correlating
        multiple suspicious behaviors.
        """

        correlations = []

        # =====================================================
        # USB Malware
        # =====================================================

        if (
            features.usb_insert > 0
            and
            features.usb_executable_run > 0
        ):

            correlations.append({

                "name": "USB Malware Activity",

                "severity": "CRITICAL",

                "description":
                    "USB device inserted and executable launched."

            })

        # =====================================================
        # Future Rules
        # =====================================================
        #
        # Internet Download
        # PowerShell
        # Certutil
        # Bitsadmin
        # Privilege Escalation
        # Curl -> Bash
        # Wget -> chmod
        # Nmap -> Hydra
        # SSH Brute Force
        # Launchctl
        # Osascript
        #
        # Add here later.
        #
        # =====================================================

        return correlations