import pytest
import time
import threading
from pathlib import Path

from zed.core.commit import CommitManager
from zed.core.repo import Repository

@pytest.fixture

def temp_repo(tmp_path):
    """Create a temporary repository."""
    repo = Repository(tmp_path)
    repo.init()
    return repo

def commit_file(repo, file_path):
    """Helper to commit a single file with default message and author."""
    commit_mgr = CommitManager(repo)
    return commit_mgr.create_commit("Test commit", "tester", [file_path])

def test_symlink_rejected(temp_repo, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("password")
    link = temp_repo.path / "link.txt"
    link.symlink_to(secret)
    with pytest.raises(ValueError):
        commit_file(temp_repo, link)

def test_large_file_blocked(temp_repo, tmp_path):
    commit_mgr = CommitManager(temp_repo)
    max_bytes = commit_mgr.config.security.max_file_size_mb * 1024 * 1024
    big = tmp_path / "big.bin"
    big.write_bytes(b"\0" * (max_bytes + 1))
    with pytest.raises(ValueError):
        commit_file(temp_repo, big)

def test_copy_then_diff_consistent(temp_repo):
    src = temp_repo.path / "a.txt"
    src.write_text("v1")
    # Start a thread to modify the file shortly after commit starts
    tid = threading.Thread(target=lambda: (time.sleep(0.01), src.write_text("v2")))
    tid.start()
    commit = commit_file(temp_repo, src)
    tid.join()
    commit_dir = temp_repo.commits_dir / commit.id
    diff_content = (commit_dir / "diff.patch").read_text()
    assert "v1" in diff_content
    assert "v2" not in diff_content 