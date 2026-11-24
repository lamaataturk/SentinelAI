
import json
import sqlite3
from contextlib import closing

from sentinelai.contracts.messages import MESSAGE_TYPES, validate_message


class SharedMemory:
    def __init__(self, db_path="sentinelai.db"):
        self.db_path = db_path

        with closing(self._connect()) as conn, conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS messages (
                    message_id TEXT PRIMARY KEY NOT NULL,
                    message_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    producer TEXT NOT NULL,
                    body TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_messages_type
                    ON messages(message_type);
            """)

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def write(self, message):
        if not isinstance(message, dict):
            raise ValueError("Message must be a dictionary")

        try:
            errors = validate_message(message)
            body = json.dumps(message, allow_nan=False)
        except (TypeError, ValueError, AttributeError, KeyError) as exc:
            raise ValueError("Malformed message") from exc

        if errors:
            raise ValueError("; ".join(errors))

        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO messages VALUES (?, ?, ?, ?, ?)",
                (
                    message["message_id"],
                    message["message_type"],
                    message["created_at"],
                    message["producer"],
                    body,
                ),
            )

    def read(self, message_type=None):
        if message_type is not None and message_type not in MESSAGE_TYPES:
            raise ValueError("Unknown message type")

        query = "SELECT body FROM messages"
        params = ()

        if message_type is not None:
            query += " WHERE message_type = ?"
            params = (message_type,)

        query += " ORDER BY rowid"

        with closing(self._connect()) as conn:
            return [
                json.loads(row[0])
                for row in conn.execute(query, params)
            ]

    def get(self, message_id):
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT body FROM messages WHERE message_id = ?",
                (message_id,),
            ).fetchone()

        return json.loads(row[0]) if row else None

    def latest_incident(self, incident_id):
        updates = [
            m for m in self.read("IncidentUpdate")
            if m["incident_id"] == incident_id
        ]

        return max(
            updates,
            key=lambda m: m["version"],
            default=None,
        )
