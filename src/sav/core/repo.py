"""Repository management for Shadow VCS."""
import sqlite3
from pathlib import Path

from filelock import FileLock


class Repository:
    """Manages a Shadow VCS repository."""

    def __init__(self, path: Path):
        """Initialize repository at given path."""
        self.path = Path(path).resolve()
        self.sav_dir = self.path / ".sav"
        self.commits_dir = self.sav_dir / "commits"
        self.fingerprints_dir = self.sav_dir / "fingerprints"
        self.db_path = self.sav_dir / "index.sqlite"
        self.lock_path = self.sav_dir / ".lock"
        self.constraints_path = self.sav_dir / "constraints.yaml"

    def init(self):
        """Initialize a new Shadow VCS repository."""
        if self.sav_dir.exists():
            raise ValueError(f"Shadow VCS repository already exists at {self.path}")

        # Create directory structure
        self.sav_dir.mkdir(exist_ok=True)
        self.commits_dir.mkdir(exist_ok=True)
        self.fingerprints_dir.mkdir(exist_ok=True)

        # Initialize SQLite database with schema
        from sav.core.db import init_database
        init_database(self.db_path)

        # Create constraints file with default conservative rules
        self.constraints_path.write_text(
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
        return self.sav_dir.exists() and self.db_path.exists()

    def validate(self) -> list[str]:
        """Validate repository structure and return list of issues."""
        issues = []
        
        if not self.sav_dir.exists():
            issues.append(".sav directory missing")
            return issues
        
        if not self.commits_dir.exists():
            issues.append("commits directory missing")
        
        if not self.fingerprints_dir.exists():
            issues.append("fingerprints directory missing")
        
        if not self.db_path.exists():
            issues.append("database file missing")
        
        if not self.constraints_path.exists():
            issues.append("constraints.yaml missing")
        
        # Validate database integrity
        try:
            from sav.core.db import verify_database_integrity
            if not verify_database_integrity(self.db_path):
                issues.append("database integrity check failed")
        except Exception as e:
            issues.append(f"database validation error: {e}")
        
        # Validate constraints file
        try:
            from sav.core.policy import PolicyManager
            policy_mgr = PolicyManager(self)
            if not policy_mgr.rules:
                issues.append("no valid policy rules found")
        except Exception as e:
            issues.append(f"policy validation error: {e}")
        
        return issues

    def get_lock(self) -> FileLock:
        """Get a file lock for repository operations."""
        return FileLock(self.lock_path, timeout=30) 