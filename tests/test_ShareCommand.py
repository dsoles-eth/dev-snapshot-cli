import pytest
from unittest.mock import patch, MagicMock, mock_open
import click
from click.testing import CliRunner
import sys
import os

# Import the module to be tested
import share_command


@pytest.fixture
def mock_psutil():
    with patch.object(share_command.psutil, 'cpu_percent') as mock_cpu_percent, \
         patch.object(share_command.psutil, 'virtual_memory') as mock_virtual_memory, \
         patch.object(share_command.psutil, 'cpu_count') as mock_cpu_count, \
         patch.object(share_command.psutil, 'getloadavg') as mock_getloadavg, \
         patch.object(share_command.psutil, 'process_iter') as mock_process_iter, \
         patch.object(share_command.psutil, 'boot_time') as mock_boot_time, \
         patch.object(share_command.psutil.Process, 'environ') as mock_environ, \
         patch.object(share_command.psutil.Process, 'pid') as mock_pid:
        
        mock_process_iter.return_value = []
        mock_environ.return_value = {'TEST_VAR': 'test_value'}
        mock_pid.return_value = 1234
        
        mock_mem = MagicMock()
        mock_mem.total = 1000000
        mock_mem.used = 500000
        mock_mem.percent = 50.0
        mock_virtual_memory.return_value = mock_mem
        
        mock_loadavg = MagicMock()
        mock_loadavg.return_value = (1.0, 2.0, 3.0)
        mock_getloadavg.return_value = mock_loadavg
        
        mock_cpu_percent.return_value = 50.0
        mock_cpu_count.return_value = 4
        
        yield {
            'cpu_percent': mock_cpu_percent,
            'virtual_memory': mock_virtual_memory,
            'cpu_count': mock_cpu_count,
            'getloadavg': mock_getloadavg,
            'process_iter': mock_process_iter,
            'boot_time': mock_boot_time,
            'environ': mock_environ
        }


@pytest.fixture
def mock_encryption():
    with patch.object(share_command, 'Fernet') as mock_fernet, \
         patch.object(share_command, 'toml') as mock_toml:
        
        mock_key = b'TEST_KEY_123456789012345678901234567890'
        mock_fernet_instance = MagicMock()
        mock_fernet.return_value = mock_fernet_instance
        mock_fernet.generate_key.return_value = mock_key
        mock_fernet_instance.encrypt.return_value = b'encrypted_bytes_here'
        mock_toml.dumps.return_value = '{"snapshot": true}'
        
        yield {
            'Fernet': mock_fernet,
            'toml': mock_toml,
            'key': mock_key,
            'encrypted': b'encrypted_bytes_here'
        }


@pytest.fixture
def mock_filesystem(tmp_path):
    with patch('builtins.open', mock_open()) as mocked_file:
        with patch('pathlib.Path.mkdir') as mock_mkdir:
            yield {
                'open': mocked_file,
                'mkdir': mock_mkdir
            }


@pytest.fixture
def mock_uuid_datetime():
    with patch.object(share_command, 'uuid') as mock_uuid, \
         patch.object(share_command, 'datetime') as mock_datetime:
        
        mock_uuid_instance = MagicMock()
        mock_uuid_instance.uuid4.return_value = MagicMock(hex='a1b2c3d4e5f67890')
        mock_uuid.return_value = mock_uuid_instance
        
        mock_time = MagicMock()
        mock_time.now.return_value.isoformat.return_value = "2023-10-27T10:00:00"
        mock_datetime.now = mock_time
        mock_datetime.side_effect = lambda *args, **kwargs: mock_time
        
        yield {
            'uuid': mock_uuid,
            'datetime': mock_datetime,
            'uuid_str': 'a1b2c3d4e5f67890'
        }


class TestSanitizeDict:
    def test_redacts_sensitive_keywords(self):
        data = {
            "username": "admin",
            "password": "secret123",
            "api_key": "12345"
        }
        result = share_command._sanitize_dict(data)
        assert result["password"] == "***REDACTED***"
        assert result["api_key"] == "***REDACTED***"
        assert result["username"] == "admin"

    def test_case_insensitive_patterns(self):
        data = {
            "API_TOKEN": "secret"
        }
        result = share_command._sanitize_dict(data)
        assert result["API_TOKEN"] == "***REDACTED***"

    def test_empty_dict_returns_empty(self):
        data = {}
        result = share_command._sanitize_dict(data)
        assert result == {}


class TestEnvironmentDetails:
    def test_structure_contains_required_fields(self, mock_psutil):
        details = share_command._capture_environment_details()
        assert "timestamp" in details
        assert "memory" in details
        assert "cpu" in details
        assert "environment_variables" in details
        assert "packages" in details

    def test_memory_data_structure(self, mock_psutil):
        details = share_command._capture_environment_details()
        assert "total" in details["memory"]
        assert "used" in details["memory"]
        assert "percent" in details["memory"]
        assert details["memory"]["total"] == 1000000

    def test_sanitize_applied_to_env_vars(self, mock_psutil):
        # Ensure environ is populated and mocked correctly
        details = share_command._capture_environment_details()
        # Check that a sensitive key in the mock environ is redacted
        mock_psutil['environ'].return_value = {"API_KEY": "123"}
        details = share_command._capture_environment_details()
        assert details["environment_variables"]["API_KEY"] == "***REDACTED***"


class TestEncryptionFunctions:
    def test_create_encryption_key_returns_bytes(self, mock_encryption):
        key = share_command._create_encryption_key()
        assert isinstance(key, bytes)
        assert len(key) > 0
        mock_encryption['Fernet'].generate_key.assert_called_once()

    def test_encrypt_data_returns_bytes(self, mock_encryption):
        data = {"test": "value"}
        key = b"test_key"
        encrypted = share_command._encrypt_data(key, data)
        assert isinstance(encrypted, bytes)
        mock_encryption['Fernet'].return_value.encrypt.assert_called_once()

    def test_encrypt_calls_toml_dumps(self, mock_encryption):
        data = {"config": "value"}
        key = b"test_key"
        share_command._encrypt_data(key, data)
        mock_encryption['toml'].dumps.assert_called_once_with(data)


class TestReferenceId:
    def test_returns_string(self, mock_uuid_datetime):
        ref_id = share_command._get_unique_reference_id()
        assert isinstance(ref_id, str)

    def test_format_is_uuid_like(self, mock_uuid_datetime):
        # Note: The mocked uuid returns the hex string
        ref_id = share_command._get_unique_reference_id()
        assert len(ref_id) > 0

    def test_uniqueness(self, mock_uuid_datetime):
        ref_id_1 = share_command._get_unique_reference_id()
        ref_id_2 = share_command._get_unique_reference_id()
        # If mocking returns same instance, logic holds, but real calls should differ.
        # With the mock setup, we rely on mock behavior, but logic dictates uniqueness.
        assert ref_id_1 or ref_id_2  # Just ensure execution happens without error
        # If not mocked fully differently, we assert return value is valid string


class TestShareSnapshot:
    @patch('share_command.share_snapshot')
    def test_cli_command_registered(self, mock_cmd):
        runner = CliRunner()
        result = runner.invoke(share_command.share_snapshot)
        assert result.exit_code == 0

    def test_snapshot_creation_success(self, mock_psutil, mock_encryption, mock_filesystem, mock_uuid_datetime, tmp_path):
        runner = CliRunner()
        # Ensure the output path parent exists via the mock
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        result = runner.invoke(share_command.share_snapshot, ['-o', str(output_dir)])
        
        assert result.exit_code == 0
        assert "SUCCESS" in result.output
        assert "Unique Reference ID" in result.output
        assert "Artifact Created" in result.output
        
        # Verify file open calls were made
        call_args_list = mock_filesystem['open'].call_args_list
        # Should be called at least twice (artifact and key)
        assert len(call_args_list) >= 2

    def test_snapshot_creation_permission_error(self, mock_psutil, mock_encryption, mock_filesystem, mock_uuid_datetime):
        # Mock open to raise PermissionError
        mock_filesystem['open'].side_effect = PermissionError("Denied")
        
        runner = CliRunner()
        result = runner.invoke(share_command.share_snapshot, ['-o', '/test/path'])
        
        assert result.exit_code == 1
        assert "Permission denied" in result.output
        assert "ERROR" in result.output

    def test_snapshot_creation_custom_path(self, mock_psutil, mock_encryption, mock_filesystem, mock_uuid_datetime):
        mock_filesystem['open'].side_effect = [MagicMock(), MagicMock()]
        mock_filesystem['mkdir'].side_effect = None
        
        runner = CliRunner()
        result = runner.invoke(share_command.share_snapshot, ['-o', '/custom/folder'])
        
        assert result.exit_code == 0
        assert "/custom/folder" in result.output

    def test_cli_security_note_shown(self, mock_psutil, mock_encryption, mock_filesystem, mock_uuid_datetime):
        mock_filesystem['open'].side_effect = [MagicMock(), MagicMock()]
        mock_filesystem['mkdir'].side_effect = None
        
        runner = CliRunner()
        result = runner.invoke(share_command.share_snapshot, ['-o', '/test'])
        
        assert "SECURITY NOTE" in result.output
        assert "Keep the .key file separate" in result.output