"""Database management for Shadow VCS."""
import logging
import shutil
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

# Schema version
SCHEMA_VERSION = 2


@contextmanager
def connect(db_path: Path, repo_path: Optional[Path] = None) -> Generator[sqlite3.Connection, None, None]:
    """Connect to the SQLite database with configurable optimizations."""
    # Import here to avoid circular imports
    from zed.core.config import get_config
    
    # Try to determine repo path from db_path if not provided
    if repo_path is None and db_path.name == "index.sqlite":
        repo_path = db_path.parent.parent  # Go from .zed/index.sqlite to repo root
    
    config = get_config(repo_path)
    timeout = config.database.timeout_seconds
    cache_size_pages = config.database.cache_size_mb * 256  # Convert MB to pages
    
    conn = sqlite3.connect(db_path, timeout=timeout)
    conn.row_factory = sqlite3.Row
    try:
        # Performance optimizations based on configuration
        if config.database.wal_mode:
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")  # Faster than FULL, still safe with WAL
        conn.execute(f"PRAGMA cache_size={cache_size_pages}")
        conn.execute("PRAGMA temp_store=MEMORY")    # Store temp tables in memory
        conn.execute("PRAGMA mmap_size=268435456")  # 256MB memory-mapped I/O
        
        if config.database.optimize_on_connect:
            conn.execute("PRAGMA optimize")         # Auto-optimize on connect
        
        yield conn
    finally:
        conn.close()


def verify_database_integrity(db_path: Path) -> bool:
    """Check database integrity and attempt recovery."""
    try:
        with connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Quick integrity check
            result = cursor.execute("PRAGMA integrity_check").fetchone()
            if result[0] != "ok":
                logging.error(f"Database integrity check failed: {result[0]}")
                return False
            
            # Check foreign key constraints
            cursor.execute("PRAGMA foreign_key_check")
            violations = cursor.fetchall()
            if violations:
                logging.error(f"Foreign key violations: {violations}")
                return False
                
            return True
    except Exception as e:
        logging.error(f"Database verification failed: {e}")
        return False


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
            if current_version == 1:
                _migrate_v1_to_v2(conn)


def _migrate_v1_to_v2(conn: sqlite3.Connection) -> None:
    """Migrate from schema v1 to v2 - add 'applied' status."""
    cursor = conn.cursor()
    
    # Create new commits table with updated status constraint
    cursor.execute("""
        CREATE TABLE commits_new (
            id TEXT PRIMARY KEY,
            message TEXT NOT NULL,
            author TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('waiting_review', 'approved', 'applied', 'rejected')),
            approved_by TEXT,
            approved_at INTEGER,
            fingerprint_id TEXT,
            FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(id)
        )
    """)
    
    # Copy data from old table
    cursor.execute("""
        INSERT INTO commits_new SELECT * FROM commits
    """)
    
    # Drop old table and rename new one
    cursor.execute("DROP TABLE commits")
    cursor.execute("ALTER TABLE commits_new RENAME TO commits")
    
    # Recreate indexes with performance improvements
    cursor.execute("CREATE INDEX idx_commits_status ON commits(status)")
    cursor.execute("CREATE INDEX idx_commits_timestamp ON commits(timestamp)")
    cursor.execute("CREATE INDEX idx_commits_author ON commits(author)")
    cursor.execute("CREATE INDEX idx_commits_status_timestamp ON commits(status, timestamp)")
    
    # Add missing indexes for other tables if they don't exist
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fingerprints_risk_score ON fingerprints(risk_score)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fingerprints_security_sensitive ON fingerprints(security_sensitive)")
    
    # Update schema version
    cursor.execute("UPDATE schema_version SET version = 2")
    
    conn.commit()


def _create_schema_v1(conn: sqlite3.Connection) -> None:
    """Create initial database schema."""
    conn.executescript(
        """
        -- Schema version tracking
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY
        );
        INSERT INTO schema_version (version) VALUES (2);

        -- Commits table
        CREATE TABLE commits (
            id TEXT PRIMARY KEY,
            message TEXT NOT NULL,
            author TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('waiting_review', 'approved', 'applied', 'rejected')),
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
        CREATE INDEX idx_commits_author ON commits(author);
        CREATE INDEX idx_commits_status_timestamp ON commits(status, timestamp);
        CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
        CREATE INDEX idx_audit_log_action ON audit_log(action);
        CREATE INDEX idx_audit_log_user ON audit_log(user);
        CREATE INDEX idx_fingerprints_commit_id ON fingerprints(commit_id);
        CREATE INDEX idx_fingerprints_risk_score ON fingerprints(risk_score);
        CREATE INDEX idx_fingerprints_security_sensitive ON fingerprints(security_sensitive);
        """
    )
    conn.commit()


def execute_bulk_operation(db_path: Path, operation_func):
    """Execute bulk database operations with optimized settings."""
    with connect(db_path) as conn:
        # Temporarily optimize for bulk operations
        conn.execute("PRAGMA synchronous=OFF")  # Fastest, but less safe
        conn.execute("BEGIN TRANSACTION")
        
        try:
            result = operation_func(conn)
            conn.execute("COMMIT")
            return result
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            # Restore safe settings
            conn.execute("PRAGMA synchronous=NORMAL")


def init_database(db_path: Path) -> None:
    """Initialize database with integrity verification."""
    # Create backup if database exists
    if db_path.exists():
        backup_path = db_path.with_suffix('.backup')
        try:
            shutil.copy2(db_path, backup_path)
            logging.info(f"Created database backup: {backup_path}")
        except Exception as e:
            logging.warning(f"Failed to create backup: {e}")
    
    try:
        with connect(db_path) as conn:
            migrate(conn)
            
        # Verify the newly created/migrated database
        if not verify_database_integrity(db_path):
            raise ValueError("Database failed integrity check after creation")
            
    except Exception as e:
        # Restore backup if available
        backup_path = db_path.with_suffix('.backup')
        if backup_path.exists() and db_path.exists():
            try:
                shutil.copy2(backup_path, db_path)
                logging.info("Restored database from backup")
                
                # Verify restored database
                if verify_database_integrity(db_path):
                    logging.info("Backup database verification successful")
                else:
                    raise ValueError("Backup database also corrupted")
                    
            except Exception as restore_error:
                logging.error(f"Failed to restore backup: {restore_error}")
                raise ValueError(f"Database initialization failed and backup restore failed: {e}") from e
        else:
            raise ValueError(f"Database initialization failed: {e}") from e 