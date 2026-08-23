"""
Generate an enriched sample database for the demo:

    100 users total
      * 97 "old" users  — present in BOTH baseline and current (each with
                          its own realistic, self-consistent normal
                          profile, so they do NOT false-alarm)
      * 3  "new" users  — present only in the current session (no baseline
                          yet -> the system's new-user handling)
      * 1  attacker (Rahim, an old user) — a multi-stage attack in the
                          current session, paired with the sample
                          Suricata / Wazuh telemetry.

Writes:
    demo/baseline_events.json   (old users' normal history)
    demo/current_events.json    (all 100 users' current session)

Run:  python scripts/generate_sample_users.py
"""

import os
import sys
import json
import random
from datetime import datetime, timedelta

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

random.seed(42)

FIRST_NAMES = [
    "Rahim", "Karim", "Sadia", "Nabil", "Tanvir", "Mitu", "Rafi", "Sumaiya",
    "Arif", "Nadia", "Hasan", "Farhan", "Imran", "Jarin", "Kamal", "Lamia",
    "Mahin", "Nusrat", "Omar", "Priya", "Quazi", "Rumana", "Sabbir", "Tania",
    "Ummay", "Vasha", "Wasim", "Xenia", "Yasmin", "Zubair", "Ayan", "Bristy",
    "Chinmoy", "Dola", "Emon", "Faria", "Galib", "Hridoy", "Ishrat", "Joy",
    "Kolpona", "Liton", "Mou", "Niloy", "Orpa", "Pial", "Rifat", "Shovon",
    "Tisha", "Utsho",
]

PROCESSES = [
    "chrome.exe", "msedge.exe", "code.exe", "outlook.exe", "teams.exe",
    "explorer.exe", "python.exe", "winword.exe", "excel.exe", "notepad.exe",
    "slack.exe", "zoom.exe", "onedrive.exe", "git.exe", "node.exe",
    "powerpnt.exe", "acrobat.exe", "spotify.exe", "postman.exe", "docker.exe",
]

# File extensions a normal user tends to work with — each user gets a small
# preferred subset so "file-type variety" is a stable per-user behaviour.
FILE_TYPES = [
    "docx", "xlsx", "pdf", "pptx", "txt", "csv", "png", "py", "md", "json",
]

BASE_DATE = datetime(2026, 7, 8)      # a Wednesday (baseline week)
CURRENT_DATE = datetime(2026, 7, 15)  # a Wednesday (current)


def ts(day, hour, minute=0):
    return (day.replace(hour=hour, minute=minute, second=0)
            ).strftime("%Y-%m-%d %H:%M:%S")


def event(timestamp, user, etype, source="Security", ip="", details=""):
    return {
        "timestamp": timestamp, "username": user, "os": "Windows",
        "event_type": etype, "source": source, "ip": ip, "details": details,
    }


def make_profile():
    return {
        "login_h": random.randint(7, 10),
        "logout_h": random.randint(16, 19),
        "n_proc": random.randint(3, 12),
        "n_file": random.randint(2, 10),
        "uses_usb": random.random() < 0.2,
        "ip": f"192.168.1.{random.randint(2, 240)}",
        "file_types": random.sample(FILE_TYPES, random.randint(2, 5)),
    }


def normal_session(user, profile, day):
    """A realistic normal working session for one user on `day`."""
    events = [event(ts(day, profile["login_h"]), user, "LOGIN_SUCCESS",
                    ip=profile["ip"], details="workstation login")]

    span = max(1, profile["logout_h"] - profile["login_h"])
    procs = random.sample(PROCESSES, min(profile["n_proc"], len(PROCESSES)))
    for name in procs:
        hour = profile["login_h"] + random.randint(0, span)
        events.append(event(
            ts(day, min(hour, 23), random.randint(0, 59)), user,
            "PROCESS_START", source="Security",
            details=f"C:\\Program Files\\{name} | {name}",
        ))

    for i in range(profile["n_file"]):
        hour = profile["login_h"] + random.randint(0, span)
        ext = random.choice(profile["file_types"])
        events.append(event(ts(day, min(hour, 23), random.randint(0, 59)),
                            user, "FILE_ACCESS", source="Explorer",
                            details=f"opened report_{i}.{ext}"))

    if profile["uses_usb"]:
        events.append(event(ts(day, profile["login_h"] + 1), user,
                            "USB_INSERT", source="USB",
                            details="known USB device"))
        events.append(event(ts(day, profile["logout_h"] - 1), user,
                            "USB_REMOVE", source="USB",
                            details="USB removed"))

    events.append(event(ts(day, profile["logout_h"]), user, "LOGOUT"))
    return events


def rahim_attack_session():
    """Rahim's multi-stage attack (pairs with sample eve.json/alerts.json)."""
    d = "2026-07-15"
    e = lambda t, et, src, det, ip="": {
        "timestamp": f"{d} {t}", "username": "Rahim", "os": "Windows",
        "event_type": et, "source": src, "ip": ip, "details": det,
    }
    return [
        e("02:30:00", "LOGIN_SUCCESS", "Security", "Night login", "203.0.113.50"),
        e("02:31:00", "USB_INSERT", "USB", "Unknown USB connected"),
        e("02:32:00", "USB_EXECUTABLE_RUN", "USB",
          "Executed invoice.pdf.exe from removable drive"),
        e("02:33:00", "POWERSHELL_START", "ProcessDetector",
          "powershell.exe launched"),
        e("02:33:30", "ENCODED_COMMAND", "ProcessDetector",
          "powershell -enc SQBmAC... (obfuscated)"),
        e("02:34:00", "SUSPICIOUS_DOWNLOAD", "FileDetector",
          "payload.exe dropped in Downloads"),
        e("02:35:00", "SENSITIVE_FILE_ACCESS", "ProcessDetector",
          "reg save hklm\\sam"),
        e("02:40:00", "LOGIN_FAILED", "Security", "Failed login", "203.0.113.50"),
        e("02:41:00", "LOGIN_FAILED", "Security", "Failed login", "203.0.113.50"),
        e("04:10:00", "LOGOUT", "Security", "Logout"),
    ]


def main():
    names = list(dict.fromkeys(FIRST_NAMES))  # unique, keep order
    while len(names) < 100:
        names.append(f"user{len(names)+1:03d}")
    names = names[:100]

    old_users = names[:97]      # have baseline + current
    new_users = names[97:]      # current only (no baseline)

    profiles = {u: make_profile() for u in names}

    baseline_events = []
    current_events = []

    for u in old_users:
        baseline_events += normal_session(u, profiles[u], BASE_DATE)
        if u == "Rahim":
            current_events += rahim_attack_session()
        else:
            current_events += normal_session(u, profiles[u], CURRENT_DATE)

    for u in new_users:
        current_events += normal_session(u, profiles[u], CURRENT_DATE)

    os.makedirs("demo", exist_ok=True)
    with open("demo/baseline_events.json", "w", encoding="utf-8") as f:
        json.dump(baseline_events, f, indent=2)
    with open("demo/current_events.json", "w", encoding="utf-8") as f:
        json.dump(current_events, f, indent=2)

    print(f"Old users (baseline + current): {len(old_users)}")
    print(f"New users (current only)      : {len(new_users)} -> {new_users}")
    print(f"baseline_events.json: {len(baseline_events)} events")
    print(f"current_events.json : {len(current_events)} events")

    _seed_history(old_users + new_users, profiles)


def _seed_history(users, profiles):
    """
    Give every user a short, plausible history of PRIOR NORMAL sessions,
    so the dashboard's trend sparkline is meaningful from the first run.
    Values are the real model features extracted from a normal session,
    then jittered across several past days. Live scans add real points on
    top of this. (Demo data only — like the rest of demo/.)
    """
    from core.event import Event
    from feature_engine.aggregator import EventAggregator
    from feature_engine.extractor import FeatureExtractor
    from models.feature_vector import ML_MODEL_FEATURES
    from core.history import write_history

    extractor = FeatureExtractor()
    history = {}

    for user in users:
        evs = [
            Event(e["timestamp"], e["username"], e["os"], e["event_type"],
                  e["source"], e["ip"], e["details"])
            for e in normal_session(user, profiles[user], BASE_DATE)
        ]
        fv = extractor.extract(evs)
        base = {f: float(getattr(fv, f, 0)) for f in ML_MODEL_FEATURES}

        snaps = []
        for _ in range(8):  # eight prior normal days
            snap = {}
            for f, v in base.items():
                if f in ("login_hour", "logout_hour"):
                    snap[f] = round(v + random.uniform(-0.6, 0.6), 2)
                elif isinstance(v, float) and v and abs(v) < 3:
                    snap[f] = round(max(0.0, v * random.uniform(0.7, 1.3)), 2)
                else:
                    snap[f] = round(max(0.0, v + v * random.uniform(-0.3, 0.3)), 2)
            snaps.append({"f": snap})
        history[user] = snaps

    write_history(history)
    print(f"session_history.json: seeded {len(history)} users x 8 sessions")


if __name__ == "__main__":
    main()
