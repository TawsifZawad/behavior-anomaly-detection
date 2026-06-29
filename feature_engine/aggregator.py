from collections import defaultdict


class EventAggregator:

    def group_by_user(self, events):

        """
        Group events by username.
        """

        grouped = defaultdict(list)

        for event in events:
            grouped[event.username].append(event)

        return grouped