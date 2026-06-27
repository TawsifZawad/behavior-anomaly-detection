from abc import ABC, abstractmethod

from core.logger import logger


class BaseCollector(ABC):
    """
    Base class for all operating system collectors.
    """

    def __init__(self, os_name):
        self.os_name = os_name

    @abstractmethod
    def collect(self):
        """
        Collect logs from the operating system.
        """
        pass

    def start(self):
        logger.info(f"{self.os_name} Collector Started")

    def stop(self):
        logger.info(f"{self.os_name} Collector Finished")