"""
Longer-horizon behavioural drift / trend detection.

The per-session anomaly model (Isolation Forest) judges ONE session
against a learned normal. It cannot see a slow shift that stays within
per-session tolerance yet, session after session, walks a user away from
their own past — the signature of a gradually-compromised account or an
insider ramping up. This module reads the rolling per-user history that
the pipeline already records (core.history) and reports features whose
RECENT window has drifted materially from the user's earlier window.

It is deliberately additive and informational: it augments the alert
narrative and the dashboard trend view, and never changes the existing
per-session decision, so reproducible detection is unaffected.
"""

from core.history import feature_series

# Behavioural dimensions worth watching for slow drift. Security-relevant
# ones (off-hours, auth failures, removable-media, network spread) are
# flagged as such so the narrative can call them out.
WATCH_FEATURES = {
    "off_hours_ratio":       ("off-hours activity", True),
    "off_hours_logon":       ("off-hours logins", True),
    "weekend_activity":      ("weekend activity", True),
    "failed_login":          ("failed logins", True),
    "removable_file_events": ("removable-media activity", True),
    "distinct_ips":          ("network sources", True),
    "event_rate":            ("activity rate", False),
    "file_access":           ("file activity", False),
    "distinct_processes":    ("program variety", False),
    "session_span":          ("session length", False),
}

# How many sessions of history before drift can be judged at all.
MIN_HISTORY = 6
# Size of the "recent" window compared against everything before it.
RECENT_WINDOW = 3
# Minimum robust z-score (shift in baseline-sigmas) to call it drift.
Z_THRESHOLD = 2.0
# Per-feature absolute floor on the baseline sigma, so a near-constant
# history does not make a tiny wobble look like huge drift.
SIGMA_FLOOR = {
    "off_hours_ratio": 0.05,
    "off_hours_logon": 1.0,
    "weekend_activity": 1.0,
    "failed_login": 1.0,
    "removable_file_events": 1.0,
    "distinct_ips": 1.0,
    "event_rate": 0.5,
    "file_access": 3.0,
    "distinct_processes": 2.0,
    "session_span": 1.0,
}


def _mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def _std(xs, mean):
    if len(xs) < 2:
        return 0.0
    return (sum((x - mean) ** 2 for x in xs) / len(xs)) ** 0.5


def detect(history, username):
    """
    Return a list of drift findings for one user, most-significant first.

    Each finding: {feature, label, direction ('up'/'down'), z, security,
    baseline, recent, text}. Empty list when there is too little history
    or nothing has drifted.
    """
    findings = []

    for feature, (label, security) in WATCH_FEATURES.items():

        series = feature_series(history, username, feature, limit=20)
        if len(series) < MIN_HISTORY:
            continue

        recent = series[-RECENT_WINDOW:]
        baseline = series[:-RECENT_WINDOW]
        if len(baseline) < 2:
            continue

        base_mean = _mean(baseline)
        base_std = max(_std(baseline, base_mean), SIGMA_FLOOR.get(feature, 1.0))
        recent_mean = _mean(recent)

        z = (recent_mean - base_mean) / base_std
        if abs(z) < Z_THRESHOLD:
            continue

        direction = "up" if z > 0 else "down"
        findings.append({
            "feature": feature,
            "label": label,
            "direction": direction,
            "z": round(z, 1),
            "security": security,
            "baseline": round(base_mean, 2),
            "recent": round(recent_mean, 2),
            "text": (
                f"{label} trending {direction} "
                f"({recent_mean:.2f} recent vs {base_mean:.2f} baseline, "
                f"{abs(z):.1f} SD over {len(series)} sessions)"
            ),
        })

    findings.sort(key=lambda f: abs(f["z"]), reverse=True)
    return findings
