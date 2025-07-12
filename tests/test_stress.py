"""Stress tests for Shadow VCS concurrent operations."""
import concurrent.futures
import tempfile
import time
from pathlib import Path

import pytest

from sav.core.commit import CommitManager
from sav.core.repo import Repository


class TestStress:
    """Stress tests for Shadow VCS."""

    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = Repository(repo_path)
            repo.init()
            yield repo

    def test_concurrent_commits(self, temp_repo):
        """Test multiple concurrent commits don't interfere."""
        commit_mgr = CommitManager(temp_repo)
        
        def create_commit(i):
            """Create a commit with a unique file."""
            test_file = temp_repo.path / f"test_{i}.py"
            test_file.write_text(f'print("Test {i}")')
            
            return commit_mgr.create_commit(
                message=f"Test commit {i}",
                author=f"test_user_{i}",
                files=[test_file]
            )
        
        # Create 10 concurrent commits
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(create_commit, i) for i in range(10)]
            commits = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # Verify all commits were created
        assert len(commits) == 10
        assert len(set(commit.id for commit in commits)) == 10  # All unique IDs
        
        # Verify all commit directories exist
        for commit in commits:
            commit_dir = temp_repo.commits_dir / commit.id
            assert commit_dir.exists()
            assert (commit_dir / "meta.json").exists()
            assert (commit_dir / "diff.patch").exists()

    def test_large_file_commit(self, temp_repo):
        """Test committing a large file."""
        commit_mgr = CommitManager(temp_repo)
        
        # Create a 1MB test file
        large_file = temp_repo.path / "large_file.txt"
        large_content = "A" * (1024 * 1024)  # 1MB of 'A's
        large_file.write_text(large_content)
        
        start_time = time.time()
        commit = commit_mgr.create_commit(
            message="Add large file",
            author="test_user",
            files=[large_file]
        )
        duration = time.time() - start_time
        
        # Should complete within reasonable time (< 5 seconds)
        assert duration < 5.0
        
        # Verify file was copied correctly
        commit_dir = temp_repo.commits_dir / commit.id
        stored_file = commit_dir / "files" / "large_file.txt"
        assert stored_file.exists()
        assert stored_file.read_text() == large_content

    def test_many_small_files(self, temp_repo):
        """Test committing many small files at once."""
        commit_mgr = CommitManager(temp_repo)
        
        # Create 100 small files
        files = []
        for i in range(100):
            test_file = temp_repo.path / f"small_{i:03d}.py"
            test_file.write_text(f'# File {i}\nprint("Hello {i}")')
            files.append(test_file)
        
        start_time = time.time()
        commit = commit_mgr.create_commit(
            message="Add 100 small files",
            author="test_user",
            files=files
        )
        duration = time.time() - start_time
        
        # Should complete within reasonable time (< 10 seconds)
        assert duration < 10.0
        
        # Verify all files were stored
        commit_dir = temp_repo.commits_dir / commit.id
        files_dir = commit_dir / "files"
        stored_files = list(files_dir.glob("small_*.py"))
        assert len(stored_files) == 100

    def test_database_integrity_under_load(self, temp_repo):
        """Test database integrity with concurrent database operations."""
        from sav.core.db import connect
        
        # First create some actual commits to reference
        commit_mgr = CommitManager(temp_repo)
        commit_ids = []
        for i in range(5):
            test_file = temp_repo.path / f"db_test_{i}.py"
            test_file.write_text(f'print("DB test {i}")')
            commit = commit_mgr.create_commit(f"DB test {i}", "test_user", [test_file])
            commit_ids.append(commit.id)
        
        def database_operation(i):
            """Perform a database operation."""
            with connect(temp_repo.db_path) as conn:
                cursor = conn.cursor()
                
                # Insert test data using valid commit IDs
                commit_id = commit_ids[i % len(commit_ids)]
                cursor.execute(
                    """
                    INSERT INTO audit_log (timestamp, action, commit_id, user, details)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (int(time.time()), f"test_action_{i}", commit_id, 
                     f"test_user_{i}", f"Test details {i}"),
                )
                conn.commit()
                
                # Read data back
                cursor.execute("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'test_action_%'")
                count = cursor.fetchone()[0]
                return count
        
        # Perform 20 concurrent database operations
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(database_operation, i) for i in range(20)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # Verify final state
        with connect(temp_repo.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'test_action_%'")
            final_count = cursor.fetchone()[0]
            assert final_count == 20

    def test_rapid_status_checks(self, temp_repo):
        """Test rapid status checks don't cause issues."""
        from sav.core.db import connect
        
        # Create some commits first
        commit_mgr = CommitManager(temp_repo)
        for i in range(5):
            test_file = temp_repo.path / f"status_test_{i}.py"
            test_file.write_text(f'print("Status test {i}")')
            commit_mgr.create_commit(f"Status test {i}", "test_user", [test_file])
        
        def check_status():
            """Check status by querying database."""
            with connect(temp_repo.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM commits")
                return cursor.fetchone()[0]
        
        # Perform 50 rapid status checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_status) for _ in range(50)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # All should return the same count
        assert all(result == 5 for result in results)

    def test_file_locking_behavior(self, temp_repo):
        """Test file locking prevents corruption during concurrent access."""
        commit_mgr = CommitManager(temp_repo)
        
        # Create a shared file
        shared_file = temp_repo.path / "shared.py"
        shared_file.write_text('print("Initial content")')
        
        def modify_and_commit(i):
            """Modify the shared file and commit."""
            # Each thread modifies the file differently
            content = f'print("Modified by thread {i}")\n# Change {i}'
            shared_file.write_text(content)
            
            return commit_mgr.create_commit(
                message=f"Modified by thread {i}",
                author=f"thread_{i}",
                files=[shared_file]
            )
        
        # Multiple threads trying to modify the same file
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(modify_and_commit, i) for i in range(3)]
            commits = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # All commits should succeed (file locking should handle conflicts)
        assert len(commits) == 3
        assert len(set(commit.id for commit in commits)) == 3 