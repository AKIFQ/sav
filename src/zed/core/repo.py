"""Repository management for Shadow VCS."""
import sqlite3
from pathlib import Path

from filelock import FileLock


class Repository:
    """Manages a Shadow VCS repository."""

    def __init__(self, path: Path):
        """Initialize repository at given path."""
        self.path = Path(path).resolve()
        self.zed_dir = self.path / ".zed"
        self.commits_dir = self.zed_dir / "commits"
        self.fingerprints_dir = self.zed_dir / "fingerprints"
        self.db_path = self.zed_dir / "index.sqlite"
        self.lock_path = self.zed_dir / ".lock"

    def init(self):
        """Initialize a new Shadow VCS repository."""
        if self.zed_dir.exists():
            raise ValueError(f"Shadow VCS repository already exists at {self.path}")

        # Create directory structure
        self.zed_dir.mkdir(exist_ok=True)
        self.commits_dir.mkdir(exist_ok=True)
        self.fingerprints_dir.mkdir(exist_ok=True)

        # Initialize SQLite database with schema
        from zed.core.db import init_database
        init_database(self.db_path)

        # Create constraints file with default conservative rules
        constraints_path = self.zed_dir / "constraints.yaml"
        constraints_path.write_text(
            """# Shadow VCS Policy Rules
# Format: match (glob), auto_approve (bool), require_role (string) or condition (Python expression)

rules:
  # Auto-approve documentation changes
  - match: "*.md"
    auto_approve: true
  
  # Auto-approve small changes
  - match: "*"
    condition: "risk_score < 0.3 and lines_added < 50"
    auto_approve: true
  
  # Block high-risk changes
  - match: "*"
    condition: "risk_score > 0.7"
    require_role: "admin"
  
  # Default: require review
  - match: "*"
    auto_approve: false
"""
        )

    def exists(self) -> bool:
        """Check if this is a valid Shadow VCS repository."""
        return self.zed_dir.exists() and self.db_path.exists()

    def get_lock(self) -> FileLock:
        """Get a file lock for repository operations."""
        return FileLock(self.lock_path, timeout=30) 