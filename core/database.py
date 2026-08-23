import sqlite3

from datetime import datetime
from core.logger import logger
from core.event import Event

DATABASE_PATH = "database/behavior.db"


def connect():
    return sqlite3.connect(DATABASE_PATH)


def create_tables():

    conn = connect()
    cursor = conn.cursor()

    # Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_record_id TEXT UNIQUE,
        timestamp TEXT,
        username TEXT,
        os TEXT,
        event_type TEXT,
        source TEXT,
        ip TEXT,
        details TEXT
    )
    """)

    # Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        os TEXT,
        first_seen TEXT,
        last_seen TEXT
    )
    """)

    # Baseline Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS baseline (
        username TEXT PRIMARY KEY,
        avg_login_hour REAL,
        avg_logout_hour REAL,
        avg_failed_login REAL,
        avg_process REAL,
        avg_usb REAL,
        avg_usb_executable_run REAL,
        avg_files REAL
    )
    """)

    # Threat History Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        timestamp TEXT,
        anomaly_score REAL,
        risk_level TEXT,
        reason TEXT
    )
    """)

    conn.commit()
    conn.close()

    logger.info("Database tables created successfully.")


def insert_event(event: Event):
    """
    Insert a normalized event into the database.
    Returns:
        True  -> Event inserted
        False -> Duplicate EventRecordID
    """

    conn = connect()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            INSERT INTO events (
                event_record_id,
                timestamp,
                username,
                os,
                event_type,
                source,
                ip,
                details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.event_record_id,
            event.timestamp,
            event.username,
            event.os,
            event.event_type,
            event.source,
            event.ip,
            event.details
        ))

        conn.commit()
        conn.close()

        logger.info(f"Event inserted for user: {event.username}")

        return True

    except sqlite3.IntegrityError:

        conn.close()

        logger.info("Duplicate EventRecordID skipped.")

        return False


def insert_events_bulk(events):
    """
    Insert many events in a single transaction (one connection,
    executemany). Duplicates (same event_record_id) are ignored. Far
    faster than calling insert_event per event when loading hundreds or
    thousands of rows. Returns the number of rows attempted.
    """

    if not events:
        return 0

    conn = connect()
    cursor = conn.cursor()

    rows = [
        (
            e.event_record_id, e.timestamp, e.username, e.os,
            e.event_type, e.source, e.ip, e.details,
        )
        for e in events
    ]

    cursor.executemany("""
        INSERT OR IGNORE INTO events (
            event_record_id, timestamp, username, os,
            event_type, source, ip, details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)

    conn.commit()
    conn.close()

    logger.info(f"Bulk inserted {len(rows)} events.")
    return len(rows)


def clear_events():

    conn = connect()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM events")

    conn.commit()
    conn.close()

    logger.info("Events table cleared.")


def get_all_events():

    conn = connect()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM events")

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_events_by_user(username):
    """
    All events for one user as (event_type, details, source, ip) rows.
    Used to pull the concrete evidence (command lines, file names,
    signatures) behind an alert for display in the dashboard.
    """

    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT event_type, details, source, ip "
        "FROM events WHERE username = ?",
        (username,),
    )

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_usb_drive_letters():
    """
    Drive letters recorded by past USB_INSERT events, as a lowercase
    set ({"e:"}). Used to correlate process execution paths with
    removable media even after the device has been unplugged.
    """

    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT details FROM events WHERE event_type = 'USB_INSERT'"
    )

    rows = cursor.fetchall()

    conn.close()

    letters = set()

    for (details,) in rows:

        if not details or "Drive=" not in details:
            continue

        value = details.split("Drive=", 1)[1].split("|", 1)[0].strip()

        for letter in value.split(","):

            letter = letter.strip().lower()

            if len(letter) == 2 and letter[1] == ":":
                letters.add(letter)

    return letters