"""Simple smoke tests for CLI functionality."""
import os
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from zed.cli import cli


class TestCLISimple:
    """Simple CLI tests."""

    def test_cli_help(self):
        """Test CLI help works."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Shadow VCS" in result.output

    def test_init_help(self):
        """Test init command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--help"])
        assert result.exit_code == 0
        assert "Initialize" in result.output

    def test_commit_help(self):
        """Test commit command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["commit", "--help"])
        assert result.exit_code == 0
        assert "Create a new commit" in result.output

    def test_status_help(self):
        """Test status command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["status", "--help"])
        assert result.exit_code == 0
        assert "Show status" in result.output

    def test_review_help(self):
        """Test review command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "Review a commit" in result.output

    def test_approve_help(self):
        """Test approve command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["approve", "--help"])
        assert result.exit_code == 0
        assert "Approve a commit" in result.output

    def test_reject_help(self):
        """Test reject command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["reject", "--help"])
        assert result.exit_code == 0
        assert "Reject a commit" in result.output

    def test_policy_help(self):
        """Test policy command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["policy", "--help"])
        assert result.exit_code == 0
        assert "Policy management" in result.output

    def test_policy_test_help(self):
        """Test policy test command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["policy", "test", "--help"])
        assert result.exit_code == 0
        assert "Test a policy rule" in result.output

    def test_basic_init_flow(self):
        """Test basic initialization flow."""
        runner = CliRunner()
        
        with runner.isolated_filesystem():
            # Test init
            result = runner.invoke(cli, ["init"])
            assert result.exit_code == 0
            assert "Initialized Shadow VCS repository" in result.output
            
            # Verify .zed directory was created
            assert Path(".zed").exists()
            assert Path(".zed/commits").exists()
            assert Path(".zed/fingerprints").exists()
            assert Path(".zed/index.sqlite").exists()
            assert Path(".zed/constraints.yaml").exists()

    def test_basic_commit_flow(self):
        """Test basic commit flow."""
        runner = CliRunner()
        
        with runner.isolated_filesystem():
            # Initialize
            runner.invoke(cli, ["init"])
            
            # Create a test file
            test_file = Path("test.txt")
            test_file.write_text("Hello, world!")
            
            # Commit the file
            result = runner.invoke(cli, ["commit", "-m", "Add test file", "test.txt"])
            assert result.exit_code == 0
            assert "Created commit" in result.output

    def test_status_empty_repo(self):
        """Test status in empty repository."""
        runner = CliRunner()
        
        with runner.isolated_filesystem():
            # Initialize
            runner.invoke(cli, ["init"])
            
            # Check status
            result = runner.invoke(cli, ["status"])
            assert result.exit_code == 0
            assert "No commits" in result.output

    def test_status_outside_repo_fails(self):
        """Test that status fails outside a repository."""
        runner = CliRunner()
        
        with runner.isolated_filesystem():
            # Don't initialize - try status
            result = runner.invoke(cli, ["status"])
            assert result.exit_code == 2  # User error - updated from 1 to 2
            assert "Not in a Shadow VCS repository" in result.output

    def test_double_init_fails(self):
        """Test that double initialization fails."""
        runner = CliRunner()
        
        with runner.isolated_filesystem():
            # Initialize once
            result = runner.invoke(cli, ["init"])
            assert result.exit_code == 0
            
            # Try to initialize again
            result = runner.invoke(cli, ["init"])
            assert result.exit_code == 2  # User error - updated from 1 to 2
            assert "already exists" in result.output 