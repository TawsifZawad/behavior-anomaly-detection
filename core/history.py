"""
Per-user session history — a small rolling record of each user's model
feature values across scans, used to draw the "recent trend" sparkline in
the dashboard's deviating-behaviour pop-up.

Stored as one JSON file: {username: [{"f": {feature: value, ...}}, ...]},
newest last, capped per user. Live scans (own/watch) accumulate real
history over time; the sample demo is seeded with plausible prior-normal
sessions by scripts/generate_sample_users.py so the trend is meaningful
from the first run.
"""

import os
import json

HISTORY_FILE = "database/session_history.json"
KEEP = 20


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def write_history(history):
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f)


def append_history(username, feature_dict, keep=KEEP):
    """
    Record one session for a user. Consecutive identical snapshots are
    de-duplicated, so re-running the reproducible demo does not pile up
    copies of the same values.
    """
    snap = {k: round(float(v), 3) for k, v in feature_dict.items()}

    history = load_history()
    entries = history.get(username, [])

    if entries and entries[-1].get("f") == snap:
        return  # nothing changed since last scan

    entries.append({"f": snap})
    history[username] = entries[-keep:]
    write_history(history)


def feature_series(history, username, feature, limit=12):
    """The recent values of one feature for one user, oldest first."""
    series = []
    for entry in history.get(username, []):
        f = entry.get("f", {})
        if feature in f:
            series.append(f[feature])
    return series[-limit:]
