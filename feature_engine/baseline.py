from core.database import connect


class BaselineManager:

    def save(self, features):

        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT OR REPLACE INTO baseline
        (
            username,
            avg_login_hour,
            avg_logout_hour,
            avg_failed_login,
            avg_process,
            avg_usb,
            avg_files
        )

        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            features.username,
            features.login_hour,
            features.logout_hour,
            features.failed_login,
            features.process_start,
            features.usb_insert,
            features.file_access
        ))

        conn.commit()
        conn.close()

    def load(self, username):

        conn = connect()

        cursor = conn.cursor()

        cursor.execute("""
        SELECT *
        FROM baseline
        WHERE username = ?
        """, (username,))

        row = cursor.fetchone()

        conn.close()

        return row