from collectors.base_collector import BaseCollector


class MacCollector(BaseCollector):

    def __init__(self):
        super().__init__("macOS")

    def collect(self):
        self.start()

        print("Collecting macOS Logs...")

        self.stop()

        return []