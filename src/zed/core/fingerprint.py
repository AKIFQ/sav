"""Fingerprint generation and risk assessment for Shadow VCS."""
import json
import time
import uuid
from pathlib import Path
from typing import Optional

from zed.core.db import connect
from zed.utils.diff import is_binary_file


class Fingerprint:
    """Represents a commit fingerprint with risk metrics."""

    def __init__(
        self,
        fingerprint_id: str,
        commit_id: str,
        files_changed: int,
        lines_added: int,
        lines_deleted: int,
        security_sensitive: bool,
        tests_passed: bool,
        risk_score: float,
        created_at: int,
    ):
        """Initialize a fingerprint."""
        self.id = fingerprint_id
        self.commit_id = commit_id
        self.files_changed = files_changed
        self.lines_added = lines_added
        self.lines_deleted = lines_deleted
        self.security_sensitive = security_sensitive
        self.tests_passed = tests_passed
        self.risk_score = risk_score
        self.created_at = created_at

    def to_dict(self) -> dict:
        """Convert fingerprint to dictionary."""
        return {
            "id": self.id,
            "commit_id": self.commit_id,
            "files_changed": self.files_changed,
            "lines_added": self.lines_added,
            "lines_deleted": self.lines_deleted,
            "security_sensitive": self.security_sensitive,
            "tests_passed": self.tests_passed,
            "risk_score": self.risk_score,
            "created_at": self.created_at,
        }


class FingerprintGenerator:
    """Generates fingerprints for commits."""

    # Security-sensitive file patterns
    SECURITY_PATTERNS = [
        ".env",
        "config",
        "secret",
        "password",
        "key",
        "token",
        "auth",
        "credential",
        ".pem",
        ".key",
        ".cert",
    ]

    def __init__(self, repo):
        """Initialize fingerprint generator with repository."""
        self.repo = repo

    def generate(self, commit, diff_stats: dict) -> Fingerprint:
        """Generate fingerprint for a commit."""
        fingerprint_id = str(uuid.uuid4())
        
        # Extract metrics from diff stats
        files_changed = diff_stats["files_changed"]
        lines_added = diff_stats["lines_added"]
        lines_deleted = diff_stats["lines_deleted"]
        
        # Check for security-sensitive files
        security_sensitive = self._check_security_sensitive(commit.files)
        
        # Check for large binary files (>500KB)
        for file_path in commit.files:
            if file_path.exists() and file_path.stat().st_size > 500 * 1024:
                security_sensitive = True
                break
        
        # For now, assume tests haven't run yet
        tests_passed = False
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(
            files_changed=files_changed,
            lines_added=lines_added,
            lines_deleted=lines_deleted,
            security_sensitive=security_sensitive,
            tests_passed=tests_passed,
            files=commit.files,
        )
        
        # Create fingerprint
        fingerprint = Fingerprint(
            fingerprint_id=fingerprint_id,
            commit_id=commit.id,
            files_changed=files_changed,
            lines_added=lines_added,
            lines_deleted=lines_deleted,
            security_sensitive=security_sensitive,
            tests_passed=tests_passed,
            risk_score=risk_score,
            created_at=int(time.time()),
        )
        
        # Save to JSON file
        fingerprint_path = self.repo.fingerprints_dir / f"{fingerprint.id}.json"
        with open(fingerprint_path, "w", encoding="utf-8") as f:
            json.dump(fingerprint.to_dict(), f, indent=2)
        
        # Save to database
        with connect(self.repo.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO fingerprints (
                    id, commit_id, files_changed, lines_added, lines_deleted,
                    security_sensitive, tests_passed, risk_score, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fingerprint.id,
                    fingerprint.commit_id,
                    fingerprint.files_changed,
                    fingerprint.lines_added,
                    fingerprint.lines_deleted,
                    1 if fingerprint.security_sensitive else 0,
                    1 if fingerprint.tests_passed else 0,
                    fingerprint.risk_score,
                    fingerprint.created_at,
                ),
            )
            
            # Update commit with fingerprint ID
            cursor.execute(
                "UPDATE commits SET fingerprint_id = ? WHERE id = ?",
                (fingerprint.id, commit.id),
            )
            
            conn.commit()
        
        return fingerprint

    def _check_security_sensitive(self, files: list[Path]) -> bool:
        """Check if any files are security-sensitive."""
        for file_path in files:
            file_str = str(file_path).lower()
            for pattern in self.SECURITY_PATTERNS:
                if pattern in file_str:
                    return True
        return False

    def _calculate_risk_score(
        self,
        files_changed: int,
        lines_added: int,
        lines_deleted: int,
        security_sensitive: bool,
        tests_passed: bool,
        files: list[Path],
    ) -> float:
        """Calculate risk score based on heuristics."""
        risk = 0.0
        
        # Base risk from change size
        if lines_added + lines_deleted > 500:
            risk += 0.3
        elif lines_added + lines_deleted > 200:
            risk += 0.2
        elif lines_added + lines_deleted > 50:
            risk += 0.1
        
        # Risk from number of files
        if files_changed > 10:
            risk += 0.2
        elif files_changed > 5:
            risk += 0.1
        
        # High risk for security-sensitive files
        if security_sensitive:
            risk += 0.4
        
        # Risk for binary files
        binary_count = sum(1 for f in files if f.exists() and is_binary_file(f))
        if binary_count > 0:
            risk += 0.3
        
        # Reduce risk if tests passed
        if tests_passed:
            risk *= 0.7
        
        # Risk for deletion-heavy changes
        if lines_deleted > lines_added * 2 and lines_deleted > 50:
            risk += 0.2
        
        # Clamp to [0, 1]
        risk = max(0.0, min(1.0, risk))
        
        return round(risk, 2)

    def get_fingerprint(self, fingerprint_id: str) -> Optional[Fingerprint]:
        """Retrieve a fingerprint by ID."""
        fingerprint_path = self.repo.fingerprints_dir / f"{fingerprint_id}.json"
        if not fingerprint_path.exists():
            return None
        
        with open(fingerprint_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        return Fingerprint(
            fingerprint_id=data["id"],
            commit_id=data["commit_id"],
            files_changed=data["files_changed"],
            lines_added=data["lines_added"],
            lines_deleted=data["lines_deleted"],
            security_sensitive=data["security_sensitive"],
            tests_passed=data["tests_passed"],
            risk_score=data["risk_score"],
            created_at=data["created_at"],
        ) 