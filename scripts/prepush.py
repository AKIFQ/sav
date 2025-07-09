#!/usr/bin/env python3
"""Pre-push hook for Shadow VCS repository.

Runs pytest and removes tests directory if all tests pass.
"""
import shutil
import subprocess
import sys
from pathlib import Path


def run_tests():
    """Run pytest and return True if all tests pass."""
    print("Running tests before push...")
    
    try:
        result = subprocess.run(
            ["pytest", "-q"],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            print("✅ All tests passed!")
            return True
        else:
            print("❌ Tests failed!")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Tests timed out after 5 minutes")
        return False
    except FileNotFoundError:
        print("❌ pytest not found - please install pytest")
        return False
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return False


def backup_tests():
    """Backup tests directory to /tmp before deletion."""
    tests_dir = Path("tests")
    if not tests_dir.exists():
        return None
    
    backup_dir = Path(f"/tmp/zed-tests-backup-{tests_dir.stat().st_mtime_ns}")
    
    try:
        shutil.copytree(tests_dir, backup_dir)
        print(f"📁 Backed up tests to {backup_dir}")
        return backup_dir
    except Exception as e:
        print(f"⚠️ Failed to backup tests: {e}")
        return None


def remove_tests():
    """Remove tests directory to keep repo lean."""
    tests_dir = Path("tests")
    if tests_dir.exists():
        try:
            shutil.rmtree(tests_dir)
            print("🗑️ Removed tests directory (keeping repo lean)")
        except Exception as e:
            print(f"⚠️ Failed to remove tests directory: {e}")


def main():
    """Main pre-push hook logic."""
    print("🚀 Shadow VCS pre-push hook")
    print("=" * 40)
    
    # Check if we're in the right directory
    if not Path("pyproject.toml").exists():
        print("❌ Not in project root (pyproject.toml not found)")
        sys.exit(1)
    
    # Run tests
    if not run_tests():
        print("\n❌ Pre-push hook failed: tests did not pass")
        print("Fix failing tests before pushing.")
        sys.exit(1)
    
    # Backup tests directory
    backup_path = backup_tests()
    
    # Remove tests directory
    remove_tests()
    
    print("\n✅ Pre-push hook completed successfully!")
    if backup_path:
        print(f"Tests backed up to: {backup_path}")
    print("Ready to push to remote repository.")


if __name__ == "__main__":
    main() 