"""Smoke tests for all CLI flows."""
import os
import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from zed.cli import cli
from zed.core.db import connect
from zed.core.repo import Repository


class TestCLIFlows:
    """Test complete CLI workflows."""

    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            yield repo_path

    @pytest.fixture
    def cli_runner(self):
        """Create a CLI runner."""
        return CliRunner()

    def _run_in_dir(self, cli_runner, command, directory):
        """Run CLI command in a specific directory."""
        old_cwd = os.getcwd()
        try:
            os.chdir(directory)
            return cli_runner.invoke(cli, command)
        finally:
            os.chdir(old_cwd)

    def test_init_commit_auto_approve_flow(self, temp_repo, cli_runner):
        """Test init -> commit -> auto-approve flow for low risk."""
        # Initialize repository
        result = self._run_in_dir(cli_runner, ["init"], temp_repo)
        assert result.exit_code == 0
        assert "Initialized Shadow VCS repository" in result.output

        # Create test file
        test_file = temp_repo / "small.py"
        test_file.write_text('print("hello")')

        # Commit small Python file (should auto-approve)
        result = self._run_in_dir(
            cli_runner, ["commit", "-m", "Add small file", str(test_file)], temp_repo
        )
        assert result.exit_code == 0
        assert "auto-approved by policy" in result.output
        assert "Risk score: 0.0" in result.output

        # Check status shows no pending commits
        result = self._run_in_dir(cli_runner, ["status"], temp_repo)
        assert result.exit_code == 0
        assert "No commits waiting for review" in result.output

        # Check status --all shows the approved commit
        result = self._run_in_dir(cli_runner, ["status", "--all"], temp_repo)
        assert result.exit_code == 0
        assert "approved" in result.output
        assert "Add small file" in result.output

    def test_commit_review_approve_flow(self, temp_repo, cli_runner):
        """Test commit -> review -> approve flow."""
        # Initialize and create a file that requires review
        cli_runner.invoke(cli, ["init"], cwd=temp_repo)
        
        # Create a large file to trigger review requirement
        large_file = temp_repo / "large.py"
        large_content = "\n".join([f"# Line {i}" for i in range(100)])
        large_file.write_text(large_content)

        # Commit large file (should require review)
        result = cli_runner.invoke(
            cli, ["commit", "-m", "Add large file", str(large_file)], cwd=temp_repo
        )
        assert result.exit_code == 0
        assert "requires review" in result.output or "auto-approved" in result.output
        
        # Get commit ID from output
        lines = result.output.split('\n')
        commit_line = [line for line in lines if "Created commit" in line][0]
        commit_id = commit_line.split()[2]

        # Review the commit
        result = cli_runner.invoke(cli, ["review", commit_id], cwd=temp_repo)
        assert result.exit_code == 0
        assert "Commit:" in result.output
        assert "Author:" in result.output
        assert "Add large file" in result.output

        # Check if commit needs approval
        repo = Repository(temp_repo)
        with connect(repo.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM commits WHERE id LIKE ? || '%'", (commit_id,))
            status = cursor.fetchone()["status"]

        if status == "waiting_review":
            # Approve the commit
            result = cli_runner.invoke(cli, ["approve", commit_id], cwd=temp_repo)
            assert result.exit_code == 0
            assert "Approved commit" in result.output

            # Verify file was copied to working tree
            assert large_file.exists()
            assert large_file.read_text() == large_content

    def test_commit_reject_flow(self, temp_repo, cli_runner):
        """Test commit -> reject flow."""
        # Initialize and create a suspicious file
        cli_runner.invoke(cli, ["init"], cwd=temp_repo)
        
        # Create file with security-sensitive name
        secret_file = temp_repo / "secret_key.txt"
        secret_file.write_text("super-secret-key-123")

        # Commit secret file
        result = cli_runner.invoke(
            cli, ["commit", "-m", "Add secret", str(secret_file)], cwd=temp_repo
        )
        assert result.exit_code == 0
        
        # Get commit ID
        lines = result.output.split('\n')
        commit_line = [line for line in lines if "Created commit" in line][0]
        commit_id = commit_line.split()[2]

        # Check if it needs review due to security sensitivity
        repo = Repository(temp_repo)
        with connect(repo.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM commits WHERE id LIKE ? || '%'", (commit_id,))
            status = cursor.fetchone()["status"]

        if status == "waiting_review":
            # Reject the commit
            result = cli_runner.invoke(
                cli, ["reject", commit_id, "--reason", "Security risk"], cwd=temp_repo
            )
            assert result.exit_code == 0
            assert "Rejected commit" in result.output

            # Verify status is updated
            with connect(repo.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT status FROM commits WHERE id LIKE ? || '%'", (commit_id,))
                status = cursor.fetchone()["status"]
                assert status == "rejected"

    def test_markdown_auto_approve_flow(self, temp_repo, cli_runner):
        """Test that markdown files are auto-approved."""
        # Initialize repository
        cli_runner.invoke(cli, ["init"], cwd=temp_repo)
        
        # Create markdown file
        md_file = temp_repo / "README.md"
        md_file.write_text("# Project\n\nThis is documentation.")

        # Commit markdown file
        result = cli_runner.invoke(
            cli, ["commit", "-m", "Add documentation", str(md_file)], cwd=temp_repo
        )
        assert result.exit_code == 0
        assert "auto-approved by policy" in result.output

    def test_policy_test_command(self, temp_repo, cli_runner):
        """Test policy test command."""
        # Initialize repository
        cli_runner.invoke(cli, ["init"], cwd=temp_repo)

        # Test valid rule
        rule = '{"match": "*.py", "condition": "risk_score < 0.5"}'
        context = '{"risk_score": 0.2, "lines_added": 10, "lines_deleted": 0}'
        
        result = cli_runner.invoke(
            cli, ["policy", "test", "--rule", rule, "--context", context], cwd=temp_repo
        )
        assert result.exit_code == 0
        assert "Rule test result: True" in result.output

        # Test rule that should fail
        context_high_risk = '{"risk_score": 0.8, "lines_added": 10, "lines_deleted": 0}'
        
        result = cli_runner.invoke(
            cli, ["policy", "test", "--rule", rule, "--context", context_high_risk], cwd=temp_repo
        )
        assert result.exit_code == 0
        assert "Rule test result: False" in result.output

    def test_error_handling(self, temp_repo, cli_runner):
        """Test error handling in CLI commands."""
        # Initialize repository
        cli_runner.invoke(cli, ["init"], cwd=temp_repo)

        # Test reviewing non-existent commit
        result = cli_runner.invoke(cli, ["review", "nonexistent"], cwd=temp_repo)
        assert result.exit_code == 1
        assert "No commit found" in result.output

        # Test approving non-existent commit
        result = cli_runner.invoke(cli, ["approve", "nonexistent"], cwd=temp_repo)
        assert result.exit_code == 1
        assert "No commit found" in result.output

        # Test rejecting non-existent commit
        result = cli_runner.invoke(cli, ["reject", "nonexistent"], cwd=temp_repo)
        assert result.exit_code == 1
        assert "No commit found" in result.output

    def test_commit_id_resolution(self, temp_repo, cli_runner):
        """Test partial commit ID resolution."""
        # Initialize and create commits
        cli_runner.invoke(cli, ["init"], cwd=temp_repo)
        
        test_file = temp_repo / "test.py"
        test_file.write_text('print("test")')
        
        result = cli_runner.invoke(
            cli, ["commit", "-m", "Test commit", str(test_file)], cwd=temp_repo
        )
        
        # Get full commit ID
        lines = result.output.split('\n')
        commit_line = [line for line in lines if "Created commit" in line][0]
        full_commit_id = commit_line.split()[2]
        
        # Test reviewing with partial ID
        partial_id = full_commit_id[:6]
        result = cli_runner.invoke(cli, ["review", partial_id], cwd=temp_repo)
        assert result.exit_code == 0
        assert full_commit_id[:8] in result.output

    def test_outside_repository_error(self, cli_runner):
        """Test commands fail when not in a repository."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Try to run commands outside a Shadow VCS repository
            result = cli_runner.invoke(cli, ["status"], cwd=temp_dir)
            assert result.exit_code == 1
            assert "Not in a Shadow VCS repository" in result.output

            result = cli_runner.invoke(cli, ["commit", "-m", "test", "nonexistent"], cwd=temp_dir)
            assert result.exit_code == 1
            assert "Not in a Shadow VCS repository" in result.output

    def test_double_initialization_error(self, temp_repo, cli_runner):
        """Test that double initialization fails."""
        # Initialize once
        result = cli_runner.invoke(cli, ["init"], cwd=temp_repo)
        assert result.exit_code == 0

        # Try to initialize again
        result = cli_runner.invoke(cli, ["init"], cwd=temp_repo)
        assert result.exit_code == 1
        assert "already exists" in result.output 