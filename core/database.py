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