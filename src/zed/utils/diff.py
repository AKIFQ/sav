"""Simple diff utility for Shadow VCS."""
import difflib
from pathlib import Path
from typing import Optional


def generate_diff(
    original_path: Path, modified_path: Path, context_lines: int = 3
) -> str:
    """Generate a unified diff between two files."""
    # Handle non-existent files
    original_lines = []
    modified_lines = []
    
    if original_path.exists():
        original_lines = original_path.read_text(encoding="utf-8").splitlines(keepends=True)
    
    if modified_path.exists():
        modified_lines = modified_path.read_text(encoding="utf-8").splitlines(keepends=True)
    
    # Generate unified diff
    diff = difflib.unified_diff(
        original_lines,
        modified_lines,
        fromfile=str(original_path),
        tofile=str(modified_path),
        n=context_lines,
    )
    
    return "".join(diff)


def calculate_diff_stats(diff_text: str) -> tuple[int, int]:
    """Calculate lines added and deleted from a diff.
    
    Returns:
        Tuple of (lines_added, lines_deleted)
    """
    lines_added = 0
    lines_deleted = 0
    
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines_added += 1
        elif line.startswith("-") and not line.startswith("---"):
            lines_deleted += 1
    
    return lines_added, lines_deleted


def is_binary_file(file_path: Path) -> bool:
    """Check if a file is binary."""
    if not file_path.exists():
        return False
    
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)  # Read first 8KB
            # Check for null bytes
            return b"\x00" in chunk
    except Exception:
        return False


def generate_file_diff(
    original_file: Optional[Path], modified_file: Path, base_path: Path
) -> dict:
    """Generate diff information for a single file.
    
    Returns:
        Dictionary with diff information including:
        - path: relative path from base
        - is_binary: whether file is binary
        - diff: diff text (empty for binary files)
        - lines_added: number of lines added
        - lines_deleted: number of lines deleted
        - is_new: whether this is a new file
        - is_deleted: whether this file was deleted
    """
    relative_path = modified_file.relative_to(base_path) if modified_file.is_relative_to(base_path) else modified_file
    
    # Check file status
    is_new = original_file is None or not original_file.exists()
    is_deleted = not modified_file.exists()
    is_binary = is_binary_file(modified_file) or (original_file and is_binary_file(original_file))
    
    # Generate diff
    diff_text = ""
    lines_added = 0
    lines_deleted = 0
    
    if not is_binary:
        if is_new:
            # New file - all lines are additions
            if modified_file.exists():
                content = modified_file.read_text(encoding="utf-8")
                lines_added = len(content.splitlines())
                diff_text = f"--- /dev/null\n+++ {relative_path}\n"
                for line in content.splitlines(keepends=True):
                    diff_text += f"+{line}"
        elif is_deleted:
            # Deleted file - all lines are deletions
            if original_file and original_file.exists():
                content = original_file.read_text(encoding="utf-8")
                lines_deleted = len(content.splitlines())
                diff_text = f"--- {relative_path}\n+++ /dev/null\n"
                for line in content.splitlines(keepends=True):
                    diff_text += f"-{line}"
        else:
            # Modified file
            diff_text = generate_diff(original_file, modified_file)
            lines_added, lines_deleted = calculate_diff_stats(diff_text)
    
    return {
        "path": str(relative_path),
        "is_binary": is_binary,
        "diff": diff_text,
        "lines_added": lines_added,
        "lines_deleted": lines_deleted,
        "is_new": is_new,
        "is_deleted": is_deleted,
    } 