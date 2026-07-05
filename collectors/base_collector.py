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
        Collect events from the operating system.
        Must return a list of normalized Event objects.
        """
        pass

    def start(self):

        logger.info(f"{self.os_name} Collector Started")

    def stop(self):

        logger.info(f"{self.os_name} Collector Finished")

    def info(self, message):

        logger.info(f"[{self.os_name}] {message}")

    def warning(self, message):

        logger.warning(f"[{self.os_name}] {message}")

    def error(self, message):

        logger.error(f"[{self.os_name}] {message}")