# Database connection helpers (SQLite)
# Maya Zeaiter
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SECURITY_DB_PATH", os.path.join(BASE_DIR, "security_system.db"))
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")


def connect_to_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create every table from schema.sql (safe to run more than once)."""
    conn = connect_to_db()
    try:
        with open(SCHEMA_PATH, "r") as f:
            conn.executescript(f.read())
        conn.commit()
    finally:
        conn.close()
