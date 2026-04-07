from typing import Dict, Any, Optional
import subprocess
import toml
from pathlib import Path
from dataclasses import dataclass, asdict

@dataclass
class GitSnapshotState:
    """Data class representing the snapshot of a git repository state."""
    branch: Optional[str]
    commit_hash: Optional[str]
    dirty_files: list[str]
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        """Converts the snapshot state to a dictionary."""
        return asdict(self)

class GitStateFetcher:
    """
    A utility class to capture the current state of a git repository.
    It retrieves branch information, commit hashes, and tracks dirty file changes
    for reproducible debugging environments.
    """

    def __init__(self, repository_path: str):
        """
        Initialize the GitStateFetcher with a specific repository path.

        Args:
            repository_path: The absolute or relative path to the git repository root.

        Raises:
            FileNotFoundError: If the repository path does not exist.
        """
        self.repository_path = Path(repository_path).resolve()
        if not self.repository_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {self.repository_path}")

    def _run_git_command(self, args: list[str]) -> str:
        """
        Execute a git command within the repository context.

        Args:
            args: List of arguments to pass to the git command.

        Returns:
            The stdout output of the command as a string.

        Raises:
            subprocess.CalledProcessError: If the git command returns a non-zero exit code.
            FileNotFoundError: If git executable is not found.
        """
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=self.repository_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise subprocess.CalledProcessError(e.returncode, e.cmd, e.stdout, e.stderr)
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Git executable not found: {e}")

    def get_branch(self) -> Optional[str]:
        """
        Retrieves the current branch name of the repository.

        Returns:
            The current branch name (e.g., 'main', 'feature-xyz') or None if failed.
        """
        try:
            return self._run_git_command(["rev-parse", "--abbrev-ref", "HEAD"])
        except Exception:
            return None

    def get_commit_hash(self) -> Optional[str]:
        """
        Retrieves the current full commit hash.

        Returns:
            The SHA-1 hash of the current commit or None if failed.
        """
        try:
            return self._run_git_command(["rev-parse", "HEAD"])
        except Exception:
            return None

    def get_dirty_files(self) -> list[str]:
        """
        Retrieves a list of files with uncommitted changes (dirty files).
        Uses `git status --porcelain` to identify modified or untracked files.

        Returns:
            A list of file paths relative to the repository root.
        """
        dirty_files = []
        try:
            output = self._run_git_command(["status", "--porcelain"])
            if output:
                lines = output.splitlines()
                for line in lines:
                    # Format: XY filename
                    if len(line) >= 3:
                        dirty_files.append(line[3:].strip())
        except Exception:
            # If git status fails, return empty list to ensure graceful degradation
            return []
        return dirty_files

    def fetch_state(self) -> Dict[str, Any]:
        """
        Captures the complete current state of the git repository.
        Aggregates branch, commit hash, and dirty files.

        Returns:
            A dictionary containing the snapshot details, or error information.
        """
        return {
            "branch": self.get_branch(),
            "commit_hash": self.get_commit_hash(),
            "dirty_files": self.get_dirty_files(),
            "path": str(self.repository_path),
            "status": "success"
        }

    def save_to_toml(self, filepath: str, state: Optional[Dict[str, Any]] = None) -> bool:
        """
        Saves the repository state to a TOML file for persistence.

        Args:
            filepath: The path where the TOML file should be saved.
            state: Optional state dictionary. If None, fetches current state.

        Returns:
            True if saved successfully, False otherwise.
        """
        try:
            if state is None:
                state = self.fetch_state()

            data = {
                "repository": str(self.repository_path),
                "snapshot": state
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                toml.dump(data, f)
            return True
        except (IOError, OSError, toml.TomlEncoderException, KeyError) as e:
            raise RuntimeError(f"Failed to save state to TOML: {e}")
        return False

    def get_serialized_state(self) -> str:
        """
        Generates a TOML string representation of the current state.

        Returns:
            The serialized state as a string.
        """
        state = self.fetch_state()
        return toml.dumps({"snapshot": state})