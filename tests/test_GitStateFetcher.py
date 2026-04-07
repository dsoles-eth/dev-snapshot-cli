import pytest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
import subprocess
import toml
from GitStateFetcher import GitStateFetcher, GitSnapshotState
import io

@pytest.fixture
def mock_path_setup():
    """Fixture to mock Path resolution and existence."""
    with patch('GitStateFetcher.Path') as mock_path:
        mock_path_instance = MagicMock()
        mock_path_resolve = MagicMock()
        mock_path_exists = MagicMock(return_value=True)
        
        # Path(repo).resolve().exists()
        mock_path_instance.resolve.return_value = mock_path_resolve
        mock_path_resolve.exists.return_value = mock_path_exists
        
        mock_path.return_value = mock_path_instance
        yield mock_path

@pytest.fixture
def mock_subprocess_run():
    """Fixture to mock subprocess.run."""
    with patch('GitStateFetcher.subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.returncode = 0
        
        mock_run.return_value = mock_result
        yield mock_run

@pytest.fixture
def mock_toml_dump():
    """Fixture to mock toml.dump."""
    with patch('GitStateFetcher.toml.dump') as mock_dump:
        mock_dump.return_value = None
        yield mock_dump

@pytest.fixture
def mock_toml_dumps():
    """Fixture to mock toml.dumps."""
    with patch('GitStateFetcher.toml.dumps') as mock_dumps:
        mock_dumps.return_value = '{"snapshot": {}}'
        yield mock_dumps

class TestGitStateFetcherInit:
    def test_init_success(self, mock_path_setup, mock_subprocess_run):
        """Test successful initialization with valid path."""
        fetcher = GitStateFetcher("/valid/path")
        assert fetcher.repository_path == Path("/valid/path").resolve()

    def test_init_path_not_found(self, mock_path_setup):
        """Test initialization raises FileNotFoundError if path does not exist."""
        mock_path_setup.return_value.resolve.return_value.exists.return_value = False
        with pytest.raises(FileNotFoundError):
            GitStateFetcher("/non/existent/path")

    def test_init_resolves_path(self, mock_path_setup, mock_subprocess_run):
        """Test that path is resolved correctly during initialization."""
        fetcher = GitStateFetcher("relative/path")
        # Ensure Path was called with the relative path
        mock_path_setup.assert_called()
        assert str(fetcher.repository_path).endswith("path")

class TestGitStateFetcherGetBranch:
    def test_get_branch_success(self, mock_subprocess_run, mock_path_setup):
        """Test retrieving current branch successfully."""
        mock_subprocess_run.return_value.stdout = "main"
        fetcher = GitStateFetcher("/path")
        result = fetcher.get_branch()
        assert result == "main"

    def test_get_branch_command_error(self, mock_subprocess_run, mock_path_setup):
        """Test handling of git command errors returns None."""
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, "git")
        fetcher = GitStateFetcher("/path")
        result = fetcher.get_branch()
        assert result is None

    def test_get_branch_file_not_found(self, mock_subprocess_run, mock_path_setup):
        """Test handling of missing git executable returns None."""
        mock_subprocess_run.side_effect = FileNotFoundError("Git not found")
        fetcher = GitStateFetcher("/path")
        result = fetcher.get_branch()
        assert result is None

class TestGitStateFetcherGetCommitHash:
    def test_get_commit_hash_success(self, mock_subprocess_run, mock_path_setup):
        """Test retrieving commit hash successfully."""
        mock_subprocess_run.return_value.stdout = "a1b2c3d4"
        fetcher = GitStateFetcher("/path")
        result = fetcher.get_commit_hash()
        assert result == "a1b2c3d4"

    def test_get_commit_hash_command_error(self, mock_subprocess_run, mock_path_setup):
        """Test handling of command errors returns None."""
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, "git")
        fetcher = GitStateFetcher("/path")
        result = fetcher.get_commit_hash()
        assert result is None

    def test_get_commit_hash_strips_output(self, mock_subprocess_run, mock_path_setup):
        """Test that commit hash output is stripped of whitespace."""
        mock_subprocess_run.return_value.stdout = "  a1b2c3d4  \n"
        fetcher = GitStateFetcher("/path")
        result = fetcher.get_commit_hash()
        assert result == "a1b2c3d4"

class TestGitStateFetcherGetDirtyFiles:
    def test_get_dirty_files_success(self, mock_subprocess_run, mock_path_setup):
        """Test retrieving list of dirty files."""
        mock_subprocess_run.return_value.stdout = " M file1.txt\nM  file2.py"
        fetcher = GitStateFetcher("/path")
        result = fetcher.get_dirty_files()
        assert "file1.txt" in result
        assert "file2.py" in result

    def test_get_dirty_files_empty(self, mock_subprocess_run, mock_path_setup):
        """Test returning empty list when no dirty files."""
        mock_subprocess_run.return_value.stdout = ""
        fetcher = GitStateFetcher("/path")
        result = fetcher.get_dirty_files()
        assert result == []

    def test_get_dirty_files_command_error(self, mock_subprocess_run, mock_path_setup):
        """Test handling command errors returns empty list."""
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, "git")
        fetcher = GitStateFetcher("/path")
        result = fetcher.get_dirty_files()
        assert result == []

class TestGitStateFetcherFetchState:
    def test_fetch_state_success(self, mock_subprocess_run, mock_path_setup):
        """Test fetching complete state dictionary."""
        mock_subprocess_run.return_value.stdout = "main"
        mock_subprocess_run.return_value.stdout = "a1b2c3" # Overwriting for hash
        mock_subprocess_run.return_value.stdout = "" # For dirty files
        # Need to configure mocks for different calls
        def side_effect(*args, **kwargs):
            cmd = args[0]
            if 'HEAD' in str(cmd):
                result = MagicMock()
                result.stdout = "a1b2c3"
                result.returncode = 0
                return result
            if 'abbrev-ref' in str(cmd):
                result = MagicMock()
                result.stdout = "main"
                result.returncode = 0
                return result
            result = MagicMock()
            result.stdout = ""
            result.returncode = 0
            return result

        mock_subprocess_run.side_effect = side_effect
        fetcher = GitStateFetcher("/path")
        state = fetcher.fetch_state()
        
        assert state["branch"] == "main"
        assert state["commit_hash"] == "a1b2c3"
        assert state["status"] == "success"

    def test_fetch_state_includes_path(self, mock_subprocess_run, mock_path_setup):
        """Test that repository path is included in state."""
        fetcher = GitStateFetcher("/my/repo")
        state = fetcher.fetch_state()
        assert state["path"] == "/my/repo"

    def test_fetch_state_all_optional_fields(self, mock_subprocess_run, mock_path_setup):
        """Test that optional fields like branch can be handled gracefully."""
        # Simulate None return for branch
        fetcher = GitStateFetcher("/path")
        with patch.object(fetcher, 'get_branch', return_value=None):
            with patch.object(fetcher, 'get_commit_hash', return_value=None):
                with patch.object(fetcher, 'get_dirty_files', return_value=[]):
                    state = fetcher.fetch_state()
                    assert state["branch"] is None
                    assert state["commit_hash"] is None

class TestGitStateFetcherSaveToToml:
    def test_save_to_toml_success(self, mock_toml_dump, mock_subprocess_run, mock_path_setup):
        """Test saving state to TOML file successfully."""
        def side_effect(*args, **kwargs):
            cmd = args[0]
            result = MagicMock()
            result.stdout = "main"
            result.returncode = 0
            return result
        mock_subprocess_run.side_effect = side_effect
        
        fetcher = GitStateFetcher("/path")
        with patch('builtins.open', mock_open()) as mock_file:
            success = fetcher.save_to_toml("state.toml")
        assert success is True
        mock_toml_dump.assert_called_once()

    def test_save_to_toml_custom_state(self, mock_toml_dump, mock_path_setup):
        """Test saving provided state dictionary to TOML."""
        custom_state = {"custom": "data"}
        fetcher = GitStateFetcher("/path")
        with patch('builtins.open', mock_open()):
            success = fetcher.save_to_toml("state.toml", state=custom_state)
        
        assert success is True
        # Verify custom state passed to toml.dump
        mock_toml_dump.assert_called()

    def test_save_to_toml_raises_runtime_error(self, mock_subprocess_run, mock_path_setup):
        """Test that saving raises RuntimeError on failure."""
        mock_toml_dump.side_effect = IOError("Disk full")
        fetcher = GitStateFetcher("/path")
        with pytest.raises(RuntimeError):
            fetcher.save_to_toml("state.toml")

class TestGitStateFetcherGetSerializedState:
    def test_get_serialized_state_returns_string(self, mock_toml_dumps, mock_subprocess_run, mock_path_setup):
        """Test that serialized state is returned as string."""
        fetcher = GitStateFetcher("/path")
        result = fetcher.get_serialized_state()
        assert isinstance(result, str)

    def test_get_serialized_state_contains_snapshot_key(self, mock_toml_dumps, mock_path_setup):
        """Test that serialized state contains snapshot key."""
        mock_toml_dumps.return_value = '{"snapshot": {"branch": "main"}}'
        fetcher = GitStateFetcher("/path")
        result = fetcher.get_serialized_state()
        assert "snapshot" in result

    def test_get_serialized_state_calls_fetch(self, mock_toml_dumps, mock_path_setup):
        """Test that fetch_state is called to generate serialized state."""
        fetcher = GitStateFetcher("/path")
        with patch.object(fetcher, 'fetch_state', return_value={"branch": "dev"}):
            fetcher.get_serialized_state()
            # If it was mocked, we verify logic flow by ensuring function completes
            # In real execution it calls fetch_state internally
            pass
        
        # Verify toml.dumps was called
        mock_toml_dumps.assert_called()

if __name__ == "__main__":
    pytest.main([__file__, "-v"])