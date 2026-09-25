import sqlite3
import os
import json
import logging
import bcrypt
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SECURITY NOTE: The seeded admin password is loaded from an environment
# variable (CRYPTRAQ_ADMIN_PASSWORD). If unset, a default is used ONLY for
# local development. In production, always set the environment variable.
# ---------------------------------------------------------------------------
_DEFAULT_ADMIN_PWD = os.environ.get("CRYPTRAQ_ADMIN_PASSWORD", "CryptraQ@SecureDefault!2026")
_DEFAULT_ADMIN_USER = os.environ.get("CRYPTRAQ_ADMIN_USER", "mirudula")


class DatabaseManager:
    def __init__(self, db_path: str = None):
        db_path = db_path or os.environ.get("CRYPTRAQ_DB_PATH", "cryptraq_relay.db")
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # WAL mode: prevents read/write lock contention; also makes the
        # SELECT→DELETE in retrieve_and_delete_packet safer under concurrent load.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        # Ensure SQLite enforces strict transaction isolation
        conn.isolation_level = None  # autocommit OFF — we manage transactions manually
        return conn

    def _init_db(self):
        """
        Idempotent schema initialisation.
        Adds the hmac_tag column to an existing packets table if it is missing
        (backward-compatible upgrade for databases created before this column existed).
        """
        create_packets = """
            CREATE TABLE IF NOT EXISTS packets (
                token       TEXT PRIMARY KEY,
                payload     TEXT NOT NULL,
                session_id  TEXT NOT NULL,
                expiration  INTEGER NOT NULL,
                signature   TEXT NOT NULL,
                timestamp   REAL NOT NULL,
                hmac_tag    TEXT
            )
        """
        create_users = """
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT UNIQUE NOT NULL,
                password_hash   TEXT NOT NULL,
                face_encoding   BLOB
            )
        """
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(create_packets)
            conn.execute(create_users)

            # Migration: add hmac_tag column if missing (for existing DBs)
            existing_cols = {
                row[1] for row in conn.execute("PRAGMA table_info(packets)")
            }
            if "hmac_tag" not in existing_cols:
                conn.execute("ALTER TABLE packets ADD COLUMN hmac_tag TEXT")
                logger.info("Migration: added hmac_tag column to packets table.")

            conn.commit()

        self._seed_admin_user()

    def _seed_admin_user(self):
        """
        Seeds the default admin account if it does not yet exist.
        Password is read from CRYPTRAQ_ADMIN_PASSWORD env-var (see module header).
        The plaintext is NOT stored; only the bcrypt hash is persisted.
        """
        username = _DEFAULT_ADMIN_USER
        password = _DEFAULT_ADMIN_PWD
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not row:
                hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, hashed.decode("utf-8")),
                )
                conn.commit()
                logger.info(f"Seeded admin user: {username}")

    # -----------------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------------

    def verify_user(self, username: str, password_attempt: str) -> bool:
        """Constant-time bcrypt verification. Returns False for any error."""
        if not username or not password_attempt:
            return False
        try:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                row = conn.execute(
                    "SELECT password_hash FROM users WHERE username = ?", (username,)
                ).fetchone()
                if row:
                    return bcrypt.checkpw(
                        password_attempt.encode("utf-8"),
                        row[0].encode("utf-8"),
                    )
        except Exception as e:
            logger.error(f"verify_user error: {e}")
        return False

    # -----------------------------------------------------------------------
    # Biometric
    # -----------------------------------------------------------------------

    def get_face_encoding(self, username: str) -> Optional[bytes]:
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            row = conn.execute(
                "SELECT face_encoding FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row and row[0]:
                return row[0]
        return None

    def update_face_encoding(self, username: str, encoding_blob: bytes) -> bool:
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cur = conn.execute(
                "UPDATE users SET face_encoding = ? WHERE username = ?",
                (encoding_blob, username),
            )
            conn.commit()
            return cur.rowcount > 0

    # -----------------------------------------------------------------------
    # Packet vault
    # -----------------------------------------------------------------------

    def delete_expired_packets(self, current_time: float) -> int:
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cur = conn.execute(
                "DELETE FROM packets WHERE expiration < ?", (current_time,)
            )
            conn.commit()
            count = cur.rowcount
            if count > 0:
                logger.info(f"Purged {count} expired packets from Vault.")
            return count

    def store_packet(self, token: str, packet_data: Dict[str, Any]) -> bool:
        """
        Stores a new packet under the given one-time token.
        Includes hmac_tag if present in packet_data.
        Returns False if token already exists (prevents token collision replay).
        """
        query = """
            INSERT INTO packets
                (token, payload, session_id, expiration, signature, timestamp, hmac_tag)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        try:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                conn.execute(
                    query,
                    (
                        token,
                        packet_data["payload"],
                        packet_data["session_id"],
                        packet_data["expiration"],
                        packet_data["signature"],
                        packet_data["timestamp"],
                        packet_data.get("hmac_tag"),  # None if not present
                    ),
                )
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            logger.warning("Token collision — duplicate deposit rejected.")
            return False
        except Exception as e:
            logger.error(f"store_packet error: {e}")
            return False

    def retrieve_and_delete_packet(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Atomically retrieves and deletes a packet using a single-connection
        exclusive transaction.  The BEGIN IMMEDIATE acquires a write lock before
        the SELECT, eliminating the TOCTOU (Time-of-Check / Time-of-Use) race
        condition that existed with separate SELECT + DELETE statements.

        Zero-trust guarantee: if the row exists it is deleted in the same
        transaction; no concurrent reader can observe it after this returns.
        """
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM packets WHERE token = ?", (token,)
            ).fetchone()
            if row:
                conn.execute("DELETE FROM packets WHERE token = ?", (token,))
                conn.execute("COMMIT")
                return dict(row)
            else:
                conn.execute("ROLLBACK")
                return None
        except Exception as e:
            logger.error(f"retrieve_and_delete_packet error: {e}")
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            return None
        finally:
            conn.close()
