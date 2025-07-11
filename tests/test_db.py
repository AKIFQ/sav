"""Tests for database module."""
import sqlite3
import tempfile
from pathlib import Path

import pytest

from zed.core.db import SCHEMA_VERSION, connect, init_database, migrate


class TestDatabase:
    """Test database operations."""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database file."""
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            db_path = Path(f.name)
        yield db_path
        db_path.unlink(missing_ok=True)

    def test_init_database(self, temp_db):
        """Test database initialization creates proper schema."""
        init_database(temp_db)

        with connect(temp_db) as conn:
            # Check schema version
            cursor = conn.cursor()
            cursor.execute("SELECT version FROM schema_version")
            version = cursor.fetchone()["version"]
            assert version == SCHEMA_VERSION

            # Check tables exist
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            tables = [row["name"] for row in cursor.fetchall()]
            expected_tables = [
                "audit_log",
                "commits",
                "fingerprints",
                "schema_version",
            ]
            assert tables == expected_tables

            # Check indexes exist
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
            )
            indexes = [row["name"] for row in cursor.fetchall()]
            expected_indexes = [
                "idx_audit_log_action",
                "idx_audit_log_timestamp",
                "idx_audit_log_user",
                "idx_commits_author",
                "idx_commits_status",
                "idx_commits_status_timestamp",
                "idx_commits_timestamp",
                "idx_fingerprints_commit_id",
                "idx_fingerprints_risk_score",
                "idx_fingerprints_security_sensitive",
            ]
            assert sorted(indexes) == sorted(expected_indexes)

    def test_connect_settings(self, temp_db):
        """Test database connection has proper settings."""
        init_database(temp_db)

        with connect(temp_db) as conn:
            # Check WAL mode
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode")
            journal_mode = cursor.fetchone()[0]
            assert journal_mode == "wal"

            # Check foreign keys enabled
            cursor.execute("PRAGMA foreign_keys")
            foreign_keys = cursor.fetchone()[0]
            assert foreign_keys == 1

    def test_migrate_existing_database(self, temp_db):
        """Test migration on existing database."""
        # Create initial database
        init_database(temp_db)

        # Run migration again (should be idempotent)
        with connect(temp_db) as conn:
            migrate(conn)

        # Verify still at correct version
        with connect(temp_db) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT version FROM schema_version")
            version = cursor.fetchone()["version"]
            assert version == SCHEMA_VERSION

    def test_row_factory(self, temp_db):
        """Test that row factory allows dict-like access."""
        init_database(temp_db)

        with connect(temp_db) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT version FROM schema_version")
            row = cursor.fetchone()
            # Test both index and key access
            assert row[0] == SCHEMA_VERSION
            assert row["version"] == SCHEMA_VERSION 