from Evtx.Evtx import Evtx


class EVTXReader:

    def __init__(self, file_path):

        self.file_path = file_path

    def read_events(self):

        """
        Read all records from an EVTX file.
        """

        events = []

        with Evtx(self.file_path) as log:

            for record in log.records():

                events.append(record.xml())

        return events