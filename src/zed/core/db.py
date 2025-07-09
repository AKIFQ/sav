"""Database management for Shadow VCS."""
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

# Schema version
SCHEMA_VERSION = 1


@contextmanager
def connect(db_path: Path) -> Generator[sqlite3.Connection, None, None]:
    """Connect to the SQLite database with proper settings."""
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
    finally:
        conn.close()


def migrate(conn: sqlite3.Connection) -> None:
    """Migrate database to current schema version."""
    # Check current version
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    )
    if not cursor.fetchone():
        # Fresh database, create all tables
        _create_schema_v1(conn)
    else:
        # Check version and migrate if needed
        cursor.execute("SELECT version FROM schema_version")
        current_version = cursor.fetchone()[0]
        if current_version < SCHEMA_VERSION:
            # Future migrations would go here
            pass


def _create_schema_v1(conn: sqlite3.Connection) -> None:
    """Create initial database schema."""
    conn.executescript(
        """
        -- Schema version tracking
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY
        );
        INSERT INTO schema_version (version) VALUES (1);

        -- Commits table
        CREATE TABLE commits (
            id TEXT PRIMARY KEY,
            message TEXT NOT NULL,
            author TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('waiting_review', 'approved', 'rejected')),
            approved_by TEXT,
            approved_at INTEGER,
            fingerprint_id TEXT,
            FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(id)
        );

        -- Fingerprints table
        CREATE TABLE fingerprints (
            id TEXT PRIMARY KEY,
            commit_id TEXT NOT NULL,
            files_changed INTEGER NOT NULL,
            lines_added INTEGER NOT NULL,
            lines_deleted INTEGER NOT NULL,
            security_sensitive INTEGER NOT NULL CHECK (security_sensitive IN (0, 1)),
            tests_passed INTEGER NOT NULL CHECK (tests_passed IN (0, 1)),
            risk_score REAL NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
            created_at INTEGER NOT NULL,
            FOREIGN KEY (commit_id) REFERENCES commits(id)
        );

        -- Audit log table
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            action TEXT NOT NULL,
            commit_id TEXT,
            user TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY (commit_id) REFERENCES commits(id)
        );

        -- Indexes for performance
        CREATE INDEX idx_commits_status ON commits(status);
        CREATE INDEX idx_commits_timestamp ON commits(timestamp);
        CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
        CREATE INDEX idx_fingerprints_commit_id ON fingerprints(commit_id);
        """
    )
    conn.commit()


def init_database(db_path: Path) -> None:
    """Initialize database with schema."""
    with connect(db_path) as conn:
        migrate(conn) 