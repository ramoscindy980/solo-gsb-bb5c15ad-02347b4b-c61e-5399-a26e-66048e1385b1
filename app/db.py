"""SQLite persistence layer (stdlib sqlite3, WAL mode)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    id              TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    redacted_text   TEXT NOT NULL,
    text_length     INTEGER NOT NULL,
    accepted_count  INTEGER NOT NULL,
    dropped_json    TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS mappings (
    document_id     TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    placeholder     TEXT NOT NULL,
    category        TEXT NOT NULL,
    start           INTEGER NOT NULL,
    "end"           INTEGER NOT NULL,
    priority        INTEGER NOT NULL,
    redacted_start  INTEGER NOT NULL,
    redacted_end    INTEGER NOT NULL,
    ciphertext      BLOB NOT NULL,
    expires_at      TEXT,               -- ISO-8601 UTC, NULL = never expires
    created_at      TEXT NOT NULL,
    PRIMARY KEY (document_id, placeholder)
);

CREATE TABLE IF NOT EXISTS restore_tokens (
    token_hash      TEXT PRIMARY KEY,   -- SHA-256 hex of the one-time token
    document_id     TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    created_at      TEXT NOT NULL,
    expires_at      TEXT,               -- ISO-8601 UTC, NULL = never expires
    used_at         TEXT                -- set once the token has been consumed
);

CREATE INDEX IF NOT EXISTS idx_mappings_doc ON mappings(document_id);
CREATE INDEX IF NOT EXISTS idx_tokens_doc  ON restore_tokens(document_id);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db(path: str) -> None:
    """Create the schema if it does not exist yet (idempotent)."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
