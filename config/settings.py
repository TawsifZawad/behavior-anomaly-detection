# Learning Mode
#
# When True, the current session's behavior is written into the baseline
# and the training dataset (used while the system is still learning what
# "normal" looks like for each user). Set to False once baselines are
# established so day-to-day runs only detect, never overwrite the baseline.

LEARNING_MODE = True


# Sample datasets used by the `bads replay` / `bads demo` commands
# (reproducible evaluation). Live runs (`bads detect`) never read these.

BASELINE_EVENT_FILE = "demo/baseline_events.json"
CURRENT_EVENT_FILE = "demo/current_events.json"


# ML datasets

ML_DATASET_FILE = "data/ml_dataset.csv"   # real + bootstrap NORMAL rows (label 0)
ML_EVAL_FILE = "data/ml_eval.csv"         # held-out NORMAL + ATTACK rows (label 1)


# Reporting / dashboard outputs

REPORTS_DIR = "reports"                    # metrics.json + charts + dashboard
ALERTS_DIR = "alerts"                      # per-alert JSON + rolling CSV
ALERTS_CSV = "alerts/alerts.csv"           # append-only alert log for the dashboard


# Network plane (Suricata) — SAMPLE feed used by `analyze` (reproducible
# demo). Do not point this at a live sensor; `analyze` must stay stable.

SURICATA_EVE_FILE = "data/network/eve.json"  # Suricata JSON event log (sample)


# SIEM plane (Wazuh) — SAMPLE feed used by `analyze`.

WAZUH_ALERTS_FILE = "data/siem/alerts.json"  # Wazuh JSON alert log (sample)


# LIVE sensor feeds used by own / detect / watch. Point these at your
# REAL Suricata / Wazuh output. Leave blank ("") to run host-only — the
# collectors skip gracefully when a path is blank or the file is absent,
# so own/live keep working on machines without Suricata/Wazuh.
#   * Suricata eve.json is usually local, e.g.
#       C:/Program Files/Suricata/log/eve.json   (Windows)
#       /var/log/suricata/eve.json               (Linux)
#   * Wazuh alerts.json is written by the MANAGER (JSON output enabled):
#       /var/ossec/logs/alerts/alerts.json
#     If the manager is on another host, point at a shared/synced copy.

LIVE_SURICATA_EVE_FILE = ""   # e.g. "C:/Program Files/Suricata/log/eve.json"
LIVE_WAZUH_ALERTS_FILE = ""   # e.g. "//server/wazuh/alerts.json"

# The live paths can also be set from OUTSIDE the program — so the
# packaged .exe can read real Suricata/Wazuh without being rebuilt. Two
# ways, in order of precedence:
#   1) environment variables  BADS_SURICATA_EVE / BADS_WAZUH_ALERTS
#   2) a plain text file  config/sensors.local.conf  (key = value)
# Both are read at start-up; whichever is set wins over the blanks above.
import os as _os


def _apply_sensor_overrides():
    global LIVE_SURICATA_EVE_FILE, LIVE_WAZUH_ALERTS_FILE

    # (2) external config file, resolved against the current working
    # directory (the app sets this to the project root at start-up, so it
    # works identically for `python bads.py` and the packaged .exe).
    conf = _os.path.join("config", "sensors.local.conf")
    if _os.path.exists(conf):
        try:
            with open(conf, encoding="utf-8") as _f:
                for _line in _f:
                    _line = _line.strip()
                    if not _line or _line.startswith("#") or "=" not in _line:
                        continue
                    _k, _v = _line.split("=", 1)
                    _k = _k.strip().upper()
                    _v = _v.strip().strip('"').strip("'")
                    if _k in ("SURICATA_EVE", "LIVE_SURICATA_EVE_FILE"):
                        LIVE_SURICATA_EVE_FILE = _v
                    elif _k in ("WAZUH_ALERTS", "LIVE_WAZUH_ALERTS_FILE"):
                        LIVE_WAZUH_ALERTS_FILE = _v
        except Exception:
            pass

    # (1) environment variables take final precedence.
    LIVE_SURICATA_EVE_FILE = _os.environ.get(
        "BADS_SURICATA_EVE", LIVE_SURICATA_EVE_FILE)
    LIVE_WAZUH_ALERTS_FILE = _os.environ.get(
        "BADS_WAZUH_ALERTS", LIVE_WAZUH_ALERTS_FILE)


_apply_sensor_overrides()


# macOS host telemetry (unified log / eslogger export, JSON per line)

MACOS_EVENTS_FILE = "data/macos/events.json"


# Minimum number of normal samples required before the Isolation Forest
# is trained on real data. Below this the bootstrap generator is used.

MIN_TRAINING_SAMPLES = 50
