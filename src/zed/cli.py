"""Command-line interface for Shadow VCS."""
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Optional

import click

from zed.core.commit import CommitManager
from zed.core.fingerprint import FingerprintGenerator
from zed.core.policy import PolicyManager
from zed.core.repo import Repository


@click.group()
@click.version_option(version="0.1.0", prog_name="zed")
def cli():
    """Shadow VCS - A local-first staging VCS for AI agents."""
    pass


@cli.command()
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    help="Path to initialize the Shadow VCS repository",
)
def init(path: Path):
    """Initialize a new Shadow VCS repository."""
    try:
        repo = Repository(path)
        repo.init()
        click.echo(f"Initialized Shadow VCS repository in {path.resolve()}/.zed")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--message",
    "-m",
    required=True,
    help="Commit message",
)
@click.option(
    "--author",
    "-a",
    default=lambda: os.environ.get("USER", "unknown"),
    help="Author name (defaults to $USER)",
)
@click.argument(
    "files",
    nargs=-1,
    required=True,
    type=click.Path(exists=True, path_type=Path),
)
def commit(message: str, author: str, files: tuple[Path, ...]):
    """Create a new commit with specified files."""
    try:
        # Find repository
        repo = _find_repository()
        
        # Convert files to list
        file_list = list(files)
        
        # Create commit
        commit_mgr = CommitManager(repo)
        commit = commit_mgr.create_commit(message, author, file_list)
        
        # Get diff stats from meta.json
        commit_dir = repo.commits_dir / commit.id
        meta_path = commit_dir / "meta.json"
        import json
        with open(meta_path, "r") as f:
            meta_data = json.load(f)
        diff_stats = meta_data["diff_stats"]
        
        # Generate fingerprint
        fingerprint_gen = FingerprintGenerator(repo)
        fingerprint = fingerprint_gen.generate(commit, diff_stats)
        
        # Evaluate policy constraints
        policy_mgr = PolicyManager(repo)
        policy_result = policy_mgr.evaluate(fingerprint, file_list)
        
        if policy_result["approved"]:
            status = "approved"
            status_msg = "auto-approved by policy"
        elif policy_result["require_role"]:
            status = "waiting_review"
            status_msg = f"requires {policy_result['require_role']} approval"
        else:
            status = "waiting_review"
            status_msg = "requires review"
        
        # Update commit status if auto-approved
        if status == "approved":
            from zed.core.db import connect
            with connect(repo.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE commits SET status = ? WHERE id = ?",
                    (status, commit.id),
                )
                conn.commit()
        
        click.echo(f"Created commit {commit.id[:8]} ({status_msg})")
        click.echo(f"  Files: {len(file_list)}")
        click.echo(f"  Lines: +{fingerprint.lines_added} -{fingerprint.lines_deleted}")
        click.echo(f"  Risk score: {fingerprint.risk_score}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--all",
    "-a",
    is_flag=True,
    help="Show all commits (default shows only pending)",
)
def status(all: bool):
    """Show status of commits."""
    try:
        repo = _find_repository()
        
        from zed.core.db import connect
        with connect(repo.db_path) as conn:
            cursor = conn.cursor()
            
            if all:
                cursor.execute(
                    "SELECT id, message, author, timestamp, status FROM commits ORDER BY timestamp DESC"
                )
            else:
                cursor.execute(
                    "SELECT id, message, author, timestamp, status FROM commits WHERE status = 'waiting_review' ORDER BY timestamp DESC"
                )
            
            commits = cursor.fetchall()
            
            if not commits:
                if all:
                    click.echo("No commits found.")
                else:
                    click.echo("No commits waiting for review.")
                return
            
            # Display commits
            for commit in commits:
                timestamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(commit["timestamp"]))
                status_color = {
                    "waiting_review": "yellow",
                    "approved": "green",
                    "rejected": "red",
                }.get(commit["status"], "white")
                
                click.echo(
                    f"{click.style(commit['id'][:8], fg='cyan')} "
                    f"{click.style(commit['status'], fg=status_color)} "
                    f"{timestamp} {commit['author']}: {commit['message']}"
                )
                
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("commit_id")
def review(commit_id: str):
    """Review a commit by showing its details."""
    try:
        repo = _find_repository()
        
        # Find commit
        commit_id = _resolve_commit_id(repo, commit_id)
        commit_mgr = CommitManager(repo)
        commit = commit_mgr.get_commit(commit_id)
        
        if not commit:
            click.echo(f"Error: Commit {commit_id[:8]} not found", err=True)
            sys.exit(1)
        
        # Get fingerprint
        fingerprint_gen = FingerprintGenerator(repo)
        fingerprint = None
        if commit.fingerprint_id:
            fingerprint = fingerprint_gen.get_fingerprint(commit.fingerprint_id)
        
        # Display commit info
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(commit.timestamp))
        click.echo(f"\nCommit: {click.style(commit.id[:8], fg='cyan')}")
        click.echo(f"Author: {commit.author}")
        click.echo(f"Date: {timestamp}")
        click.echo(f"Status: {click.style(commit.status, fg='yellow')}")
        click.echo(f"Message: {commit.message}")
        
        if fingerprint:
            click.echo(f"\nFingerprint:")
            click.echo(f"  Risk score: {fingerprint.risk_score}")
            click.echo(f"  Files changed: {fingerprint.files_changed}")
            click.echo(f"  Lines: +{fingerprint.lines_added} -{fingerprint.lines_deleted}")
            click.echo(f"  Security sensitive: {'Yes' if fingerprint.security_sensitive else 'No'}")
        
        click.echo(f"\nFiles:")
        for file_path in commit.files:
            click.echo(f"  {file_path}")
        
        # Show diff
        diff_path = repo.commits_dir / commit.id / "diff.patch"
        if diff_path.exists():
            click.echo(f"\nDiff:")
            click.echo("-" * 60)
            diff_content = diff_path.read_text(encoding="utf-8")
            if diff_content:
                click.echo(diff_content)
            else:
                click.echo("(No changes)")
            click.echo("-" * 60)
            
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("commit_id")
@click.option(
    "--user",
    "-u",
    default=lambda: os.environ.get("USER", "unknown"),
    help="User approving the commit",
)
def approve(commit_id: str, user: str):
    """Approve a commit and apply it to the working tree."""
    try:
        repo = _find_repository()
        
        # Find commit
        commit_id = _resolve_commit_id(repo, commit_id)
        commit_mgr = CommitManager(repo)
        commit = commit_mgr.get_commit(commit_id)
        
        if not commit:
            click.echo(f"Error: Commit {commit_id[:8]} not found", err=True)
            sys.exit(1)
        
        if commit.status == "approved":
            click.echo(f"Commit {commit_id[:8]} is already approved", err=True)
            sys.exit(1)
        
        if commit.status == "rejected":
            click.echo(f"Commit {commit_id[:8]} has been rejected", err=True)
            sys.exit(1)
        
        # Copy files to working tree
        commit_dir = repo.commits_dir / commit.id
        files_dir = commit_dir / "files"
        
        copied_files = []
        for stored_file in files_dir.rglob("*"):
            if stored_file.is_file():
                relative_path = stored_file.relative_to(files_dir)
                dest_path = repo.path / relative_path
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(stored_file, dest_path)
                copied_files.append(relative_path)
        
        # Update database
        from zed.core.db import connect
        with connect(repo.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE commits SET status = ?, approved_by = ?, approved_at = ? WHERE id = ?",
                ("approved", user, int(time.time()), commit.id),
            )
            
            # Add to audit log
            cursor.execute(
                """
                INSERT INTO audit_log (timestamp, action, commit_id, user, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    int(time.time()),
                    "commit_approved",
                    commit.id,
                    user,
                    f"Applied {len(copied_files)} files to working tree",
                ),
            )
            
            conn.commit()
        
        click.echo(f"Approved commit {commit.id[:8]}")
        click.echo(f"Applied {len(copied_files)} files to working tree")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("commit_id")
@click.option(
    "--user",
    "-u",
    default=lambda: os.environ.get("USER", "unknown"),
    help="User rejecting the commit",
)
@click.option(
    "--reason",
    "-r",
    help="Reason for rejection",
)
def reject(commit_id: str, user: str, reason: Optional[str]):
    """Reject a commit."""
    try:
        repo = _find_repository()
        
        # Find commit
        commit_id = _resolve_commit_id(repo, commit_id)
        commit_mgr = CommitManager(repo)
        commit = commit_mgr.get_commit(commit_id)
        
        if not commit:
            click.echo(f"Error: Commit {commit_id[:8]} not found", err=True)
            sys.exit(1)
        
        if commit.status == "approved":
            click.echo(f"Commit {commit_id[:8]} is already approved", err=True)
            sys.exit(1)
        
        if commit.status == "rejected":
            click.echo(f"Commit {commit_id[:8]} is already rejected", err=True)
            sys.exit(1)
        
        # Update database
        from zed.core.db import connect
        with connect(repo.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE commits SET status = ? WHERE id = ?",
                ("rejected", commit.id),
            )
            
            # Add to audit log
            details = f"Rejected commit"
            if reason:
                details += f": {reason}"
            
            cursor.execute(
                """
                INSERT INTO audit_log (timestamp, action, commit_id, user, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    int(time.time()),
                    "commit_rejected",
                    commit.id,
                    user,
                    details,
                ),
            )
            
            conn.commit()
        
        click.echo(f"Rejected commit {commit.id[:8]}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def policy():
    """Policy management commands."""
    pass


@policy.command()
@click.option(
    "--rule",
    "-r",
    required=True,
    help="Rule to test (JSON format)",
)
@click.option(
    "--context",
    "-c",
    required=True,
    help="Test context (JSON format with risk_score, lines_added, lines_deleted)",
)
def test(rule: str, context: str):
    """Test a policy rule with given context."""
    try:
        import json
        
        repo = _find_repository()
        policy_mgr = PolicyManager(repo)
        
        # Parse inputs
        rule_dict = json.loads(rule)
        test_context = json.loads(context)
        
        # Test the rule
        result = policy_mgr.test_rule(rule_dict, test_context)
        
        click.echo(f"Rule test result: {result}")
        click.echo(f"Rule: {rule}")
        click.echo(f"Context: {context}")
        
    except json.JSONDecodeError as e:
        click.echo(f"Error: Invalid JSON - {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def _find_repository() -> Repository:
    """Find the Shadow VCS repository in current or parent directories."""
    current = Path.cwd()
    while current != current.parent:
        repo = Repository(current)
        if repo.exists():
            return repo
        current = current.parent
    
    raise ValueError("Not in a Shadow VCS repository")


def _resolve_commit_id(repo: Repository, partial_id: str) -> str:
    """Resolve a partial commit ID to full ID."""
    from zed.core.db import connect
    
    with connect(repo.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM commits WHERE id LIKE ? || '%'",
            (partial_id,),
        )
        matches = cursor.fetchall()
        
        if not matches:
            raise ValueError(f"No commit found matching {partial_id}")
        
        if len(matches) > 1:
            raise ValueError(f"Ambiguous commit ID {partial_id}, matches {len(matches)} commits")
        
        return matches[0]["id"]


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main() 