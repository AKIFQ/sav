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

    def create_commit(
        self, message: str, author: str, files: list[Path]
    ) -> Commit:
        """Create a new commit."""
        # Validate files exist
        for file_path in files:
            if not file_path.exists():
                raise ValueError(f"File does not exist: {file_path}")

        # Create commit
        commit = Commit.create(message, author, files)

        # Acquire lock for commit operations
        with self.repo.get_lock():
            # Create commit directory
            commit_dir = self.repo.commits_dir / commit.id
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

            # Generate diffs
            diff_data = []
            total_lines_added = 0
            total_lines_deleted = 0
            
            for file_path in files:
                relative_path = file_path.relative_to(self.repo.path) if file_path.is_relative_to(self.repo.path) else file_path.name
                # For now, treat all files as new (no comparison with working tree)
                diff_info = generate_file_diff(None, file_path, self.repo.path)
                diff_data.append(diff_info)
                total_lines_added += diff_info["lines_added"]
                total_lines_deleted += diff_info["lines_deleted"]

            # Write diff.patch
            diff_patch_path = commit_dir / "diff.patch"
            with open(diff_patch_path, "w", encoding="utf-8") as f:
                for diff_info in diff_data:
                    if diff_info["diff"]:
                        f.write(diff_info["diff"])
                        f.write("\n\n")

            # Write meta.json
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
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta_data, f, indent=2)

            # Insert into database
            with connect(self.repo.db_path) as conn:
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

        return commit

    def get_commit(self, commit_id: str) -> Optional[Commit]:
        """Retrieve a commit by ID."""
        with connect(self.repo.db_path) as conn:
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