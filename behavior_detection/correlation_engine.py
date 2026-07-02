class CorrelationEngine:

    def analyze(self, comparison):

        correlations = []

        usb_insert = comparison["usb_insert"]["status"] == "changed"

        usb_exe = comparison["usb_executable_run"]["status"] == "changed"

        if usb_insert and usb_exe:

            correlations.append({

                "name": "USB Malware Activity",

                "severity": "CRITICAL",

                "description": (
                    "USB device inserted and executable launched."
                )

            })

        return correlations