from collectors.base_collector import BaseCollector


class UbuntuCollector(BaseCollector):

    def __init__(self):
        super().__init__("Ubuntu")

    def collect(self):
        self.start()

        print("Collecting Ubuntu Logs...")

        self.stop()

        return []