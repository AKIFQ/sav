"""Commit management for Shadow VCS."""
import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Optional

from filelock import FileLock

from zed.core.db import connect
from zed.utils.diff import generate_file_diff


class Commit:
    """Represents a Shadow VCS commit."""

    def __init__(
        self,
        commit_id: str,
        message: str,
        author: str,
        timestamp: int,
        files: list[Path],
        status: str = "waiting_review",
    ):
        """Initialize a commit."""
        self.id = commit_id
        self.message = message
        self.author = author
        self.timestamp = timestamp
        self.files = files
        self.status = status
        self.fingerprint_id: Optional[str] = None

    @classmethod
    def create(
        cls, message: str, author: str, files: list[Path]
    ) -> "Commit":
        """Create a new commit with generated ID and timestamp."""
        commit_id = str(uuid.uuid4())
        timestamp = int(time.time())
        return cls(commit_id, message, author, timestamp, files)

    def to_dict(self) -> dict:
        """Convert commit to dictionary."""
        return {
            "id": self.id,
            "message": self.message,
            "author": self.author,
            "timestamp": self.timestamp,
            "files": [str(f) for f in self.files],
            "status": self.status,
            "fingerprint_id": self.fingerprint_id,
        }


class CommitManager:
    """Manages commit operations."""

    def __init__(self, repo):
        """Initialize commit manager with repository."""
        self.repo = repo
        
        # Import here to avoid circular imports
        from zed.core.config import get_config
        self.config = get_config(repo.path)

    def _atomic_write(self, target_path: Path, content: str):
        """Write content atomically to prevent corruption."""
        temp_path = target_path.with_suffix('.tmp')
        try:
            temp_path.write_text(content, encoding='utf-8')
            if hasattr(os, 'fsync'):
                with open(temp_path, 'r+b') as f:
                    f.flush()
                    os.fsync(f.fileno())  # Force write to disk
            temp_path.replace(target_path)  # Atomic on Unix/Windows
        except Exception:
            temp_path.unlink(missing_ok=True)  # Cleanup on failure
            raise

    def _validate_file_path(self, file_path: Path) -> Path:
        """Ensure file path is safe and within repository bounds."""
        try:
            resolved = file_path.resolve()
            # Disallow symlinks to prevent symlink bypass
            if file_path.is_symlink():
                raise ValueError(f"Symlinks are not allowed: {file_path}")
            repo_root = self.repo.path.resolve()
            
            # Check if file is within repository
            resolved.relative_to(repo_root)
            
            # Block path traversal attempts
            if '..' in file_path.parts:
                raise ValueError(f"Path traversal not allowed: {file_path}")
                
            return resolved
        except ValueError as e:
            raise ValueError(f"Invalid file path: {file_path}") from e

    def _check_file_size(self, file_path: Path):
        """Prevent commits of oversized files."""
        if not file_path.exists():
            return
            
        size = file_path.stat().st_size
        max_size_bytes = self.config.security.max_file_size_mb * 1024 * 1024
        
        if size > max_size_bytes:
            size_mb = size / (1024 * 1024)
            limit_mb = self.config.security.max_file_size_mb
            raise ValueError(
                f"File too large: {file_path} ({size_mb:.1f}MB) "
                f"exceeds limit ({limit_mb}MB). "
                f"Use Git LFS for large files."
            )

    def create_commit(
        self, message: str, author: str, files: list[Path]
    ) -> Commit:
        """Create commit with full rollback on any failure."""
        # Validate inputs first
        for file_path in files:
            self._validate_file_path(file_path)
            self._check_file_size(file_path)
            if not file_path.exists():
                raise ValueError(f"File does not exist: {file_path}")

        commit = Commit.create(message, author, files)
        commit_dir = self.repo.commits_dir / commit.id
        
        try:
            with self.repo.get_lock():
                # Create directory structure
                commit_dir.mkdir(parents=True, exist_ok=True)
                
                # Copy files to commit directory
                files_dir = commit_dir / "files"
                files_dir.mkdir(exist_ok=True)
                
                file_mappings = []
                for file_path in files:
                    relative_path = file_path.relative_to(self.repo.path) if file_path.is_relative_to(self.repo.path) else file_path.name
                    dest_path = files_dir / relative_path
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file_path, dest_path)
                    file_mappings.append({
                        "original": str(file_path),
                        "relative": str(relative_path),
                        "stored": str(dest_path.relative_to(commit_dir))
                    })
                # Generate diffs against the stable shadow copy to avoid race conditions
                diff_data = []
                total_lines_added = 0
                total_lines_deleted = 0

                for fm in file_mappings:
                    shadow_file = commit_dir / fm["stored"]
                    # Pre-size guard before reading file
                    size = shadow_file.stat().st_size
                    max_size = self.config.security.max_file_size_mb * 1024 * 1024
                    if size > max_size:
                        size_mb = size / (1024 * 1024)
                        limit_mb = self.config.security.max_file_size_mb
                        raise ValueError(
                            f"File too large: {shadow_file} ({size_mb:.1f}MB) "
                            f"exceeds limit ({limit_mb}MB). Use Git LFS for large files."
                        )
                    # Generate diff from empty (new file) to shadow copy
                    diff_info = generate_file_diff(None, shadow_file, commit_dir)
                    diff_data.append(diff_info)
                    total_lines_added += diff_info["lines_added"]
                    total_lines_deleted += diff_info["lines_deleted"]

                # Write diff.patch atomically
                diff_patch_path = commit_dir / "diff.patch"
                diff_content = ""
                for diff_info in diff_data:
                    if diff_info["diff"]:
                        diff_content += diff_info["diff"] + "\n\n"
                self._atomic_write(diff_patch_path, diff_content)

                # Write meta.json atomically
                meta_data = {
                    "id": commit.id,
                    "message": commit.message,
                    "author": commit.author,
                    "timestamp": commit.timestamp,
                    "status": commit.status,
                    "files": file_mappings,
                    "diff_stats": {
                        "files_changed": len(files),
                        "lines_added": total_lines_added,
                        "lines_deleted": total_lines_deleted,
                    },
                }
                
                meta_path = commit_dir / "meta.json"
                self._atomic_write(meta_path, json.dumps(meta_data, indent=2))

                # Insert into database
                with connect(self.repo.db_path, self.repo.path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO commits (id, message, author, timestamp, status, fingerprint_id)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            commit.id,
                            commit.message,
                            commit.author,
                            commit.timestamp,
                            commit.status,
                            commit.fingerprint_id,
                        ),
                    )
                    
                    # Add to audit log
                    cursor.execute(
                        """
                        INSERT INTO audit_log (timestamp, action, commit_id, user, details)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            int(time.time()),
                            "commit_created",
                            commit.id,
                            commit.author,
                            f"Created commit with {len(files)} files",
                        ),
                    )
                    
                    conn.commit()

        except Exception as e:
            # Rollback: clean up any partial state
            if commit_dir.exists():
                shutil.rmtree(commit_dir, ignore_errors=True)
                
            # Clean up database entries
            try:
                with connect(self.repo.db_path, self.repo.path) as conn:
                    conn.execute("DELETE FROM commits WHERE id = ?", (commit.id,))
                    conn.execute("DELETE FROM audit_log WHERE commit_id = ?", (commit.id,))
                    conn.commit()
            except Exception:
                pass  # Database might not have entries yet
                
            raise ValueError(f"Commit failed: {e}") from e

        return commit

    def get_commit(self, commit_id: str) -> Optional[Commit]:
        """Retrieve a commit by ID."""
        with connect(self.repo.db_path, self.repo.path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM commits WHERE id = ?",
                (commit_id,),
            )
            row = cursor.fetchone()
            
            if not row:
                return None
            
            # Load files from meta.json
            commit_dir = self.repo.commits_dir / commit_id
            meta_path = commit_dir / "meta.json"
            
            if not meta_path.exists():
                return None
            
            with open(meta_path, "r", encoding="utf-8") as f:
                meta_data = json.load(f)
            
            files = [Path(fm["original"]) for fm in meta_data["files"]]
            
            commit = Commit(
                commit_id=row["id"],
                message=row["message"],
                author=row["author"],
                timestamp=row["timestamp"],
                files=files,
                status=row["status"],
            )
            commit.fingerprint_id = row["fingerprint_id"]
            
            return commit 