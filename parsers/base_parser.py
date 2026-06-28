from abc import ABC, abstractmethod


class BaseParser(ABC):

    @abstractmethod
    def parse(self, raw_event):
        """
        Convert raw OS event
        into a normalized Event object.
        """
        pass