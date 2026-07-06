import sqlite3

DB_NAME = "database/behavior.db"


class DuplicateRemover:

    def __init__(self):

        self.connection = sqlite3.connect(DB_NAME)
        self.cursor = self.connection.cursor()

    def remove_duplicates(self):

        print("Checking for duplicate events...")

        # Count before cleanup
        self.cursor.execute(
            "SELECT COUNT(*) FROM events"
        )
        before = self.cursor.fetchone()[0]

        # Delete duplicate rows while keeping the first row
        self.cursor.execute("""
            DELETE FROM events
            WHERE rowid NOT IN (
                SELECT MIN(rowid)
                FROM events
                GROUP BY
                    username,
                    event_type,
                    timestamp,
                    details
            )
        """)

        self.connection.commit()

        # Count after cleanup
        self.cursor.execute(
            "SELECT COUNT(*) FROM events"
        )
        after = self.cursor.fetchone()[0]

        print(f"Before : {before}")
        print(f"After  : {after}")
        print(f"Removed: {before - after}")

    def close(self):

        self.connection.close()


if __name__ == "__main__":

    remover = DuplicateRemover()

    remover.remove_duplicates()

    remover.close()