import os
import logging

# Detailed logs (every event insert, collector step, ...) go to a file so
# the terminal stays clean and shows only the detection output that the
# CLI prints. Warnings and errors still surface on the console.
#
# Set BADS_DEBUG=1 to also stream INFO logs to the console.

os.makedirs("logs", exist_ok=True)

logger = logging.getLogger("BehaviorMonitor")
logger.setLevel(logging.INFO)
logger.propagate = False  # don't let records reach the root/stderr handler

if not logger.handlers:

    _formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    _file = logging.FileHandler("logs/bads.log", encoding="utf-8")
    _file.setLevel(logging.INFO)
    _file.setFormatter(_formatter)
    logger.addHandler(_file)

    # Console handler: quiet by default (warnings/errors only); verbose
    # when BADS_DEBUG is set.
    _console = logging.StreamHandler()
    _console.setLevel(
        logging.INFO if os.environ.get("BADS_DEBUG") else logging.WARNING
    )
    _console.setFormatter(_formatter)
    logger.addHandler(_console)
