import pytest
from unittest.mock import MagicMock, patch, mock_open
import os
import sys
import tempfile
import uuid
from cryptography.fernet import Fernet

from RestoreUtility import SnapshotDecryptor, SnapshotRestorer, restore_cli, restore_command, verify_status


@pytest.fixture
def encryption_key():
    """Generate a fresh encryption key for testing."""
    return Fernet.generate_key()


@pytest.fixture
def valid_snapshot_data():
    """Provide a valid snapshot data structure for testing."""
    return {
        'environment': {
            'PYTHONPATH': '/custom/path',
            'DB_HOST': 'localhost',
            'DEBUG': 'True'
        },
        'configs': [
            {'type': 'process', 'name': 'service_a', 'action': 'restart'}
        ]
    }


@pytest.fixture
def encrypted_snapshot_content():
    """Generate encrypted content for a valid snapshot."""
    key = Fernet.generate_key()
    fernet = Fernet(key)
    data = {'environment': {'TEST_VAR': 'test_value'}, 'configs': []}
    encrypted = fernet.encrypt(str(data).encode('utf-8'))
    return encrypted.decode('utf-8')


@pytest.fixture
def mock_toml_module():
    """Mock the toml module to prevent actual parsing."""
    with patch('toml.loads') as mock_toml:
        yield mock_toml


@pytest.fixture
def temp_snapshot_file(tmp_path, valid_snapshot_data, encryption_key):
    """Create a temporary snapshot file with encrypted content."""
    fernet = Fernet(encryption_key)
    content = str(valid_snapshot_data)
    encrypted_content = fernet.encrypt(content.encode('utf-8')).decode('utf-8')
    file_path = tmp_path / "test_snapshot.toml"
    with open(file_path, 'w') as f:
        f.write(encrypted_content)
    return str(file_path), encryption_key, valid_snapshot_data


@pytest.fixture
def mock_psutil():
    """Mock psutil process checks."""
    with patch('psutil.process_iter') as mock_iter:
        mock_process = MagicMock()
        mock_process.name.return_value = 'python'
        mock_iter.return_value = [mock_process]
        yield mock_iter


@pytest.fixture
def mock_env_vars():
    """Mock os.environ operations."""
    with patch('os.environ') as mock_env:
        mock_env.__setitem__ = MagicMock()
        mock_env.__getitem__ = MagicMock(return_value=None)
        mock_env.keys = MagicMock(return_value=set())
        yield mock_env


class TestSnapshotDecryptor:
    """Tests for SnapshotDecryptor class."""

    @patch('cryptography.fernet.Fernet')
    def test_init_with_provided_key(self, mock_fernet, encryption_key):
        """Test initialization with provided encryption key."""
        decryptor = SnapshotDecryptor(key=encryption_key)
        assert decryptor.key == encryption_key
        assert hasattr(decryptor, 'fernet')

    @patch('os.environ.get')
    @patch('cryptography.fernet.Fernet')
    def test_init_from_environment(self, mock_fernet, mock_env_get, encryption_key):
        """Test initialization loading key from environment variable."""
        mock_env_get.return_value = 'test_env_key'
        mock_fernet.return_value.encrypt.return_value = b'test_encrypted'
        
        decryptor = SnapshotDecryptor(key=None)
        assert decryptor.key == b'test_env_key'

    @patch('cryptography.fernet.Fernet.generate_key')
    @patch('os.environ.get')
    def test_init_generates_new_key_when_missing(self, mock_env_get, mock_generate, encryption_key):
        """Test initialization generates new key when none provided."""
        mock_env_get.return_value = None
        mock_generate.return_value = encryption_key
        
        decryptor = SnapshotDecryptor(key=None)
        assert decryptor.key == encryption_key

    @patch('cryptography.fernet.Fernet')
    def test_encrypt_data_success(self, mock_fernet, encryption_key):
        """Test successful encryption of data."""
        mock_fernet.return_value.encrypt.return_value = b'test_encrypted_data'
        decryptor = SnapshotDecryptor(key=encryption_key)
        
        result = decryptor.encrypt_data('test_plaintext')
        assert result == 'test_encrypted_data'

    @patch('cryptography.fernet.Fernet')
    def test_encrypt_data_failure_raises_error(self, mock_fernet):
        """Test that encryption failure raises ValueError."""
        mock_fernet.return_value.encrypt.side_effect = Exception("Crypto error")
        decryptor = SnapshotDecryptor(key=b'some_key')
        
        with pytest.raises(ValueError) as exc_info:
            decryptor.encrypt_data('test_data')
        assert "Encryption failed" in str(exc_info.value)

    @patch('cryptography.fernet.Fernet')
    def test_decrypt_data_success(self, mock_fernet, encryption_key):
        """Test successful decryption of data."""
        mock_fernet.return_value.decrypt.return_value = b'test_decrypted_data'
        decryptor = SnapshotDecryptor(key=encryption_key)
        
        result = decryptor.decrypt_data('test_encrypted_data')
        assert result == 'test_decrypted_data'

    @patch('cryptography.fernet.Fernet')
    def test_decrypt_data_failure_raises_error(self, mock_fernet):
        """Test that decryption failure raises ValueError."""
        mock_fernet.return_value.decrypt.side_effect = Exception("Decrypt error")
        decryptor = SnapshotDecryptor(key=b'some_key')
        
        with pytest.raises(ValueError) as exc_info:
            decryptor.decrypt_data('test_data')
        assert "Decryption failed" in str(exc_info.value)


class TestSnapshotRestorer:
    """Tests for SnapshotRestorer class."""

    def test_init_creates_restorer(self):
        """Test initialization creates restorer with correct ID."""
        restorer = SnapshotRestorer("test_id_001")
        assert restorer.restorer_id == "test_id_001"
        assert restorer.encryption_manager is None

    @patch('RestoreUtility.SnapshotDecryptor')
    def test_set_encryption_key_configures_manager(self, mock_decryptor_class):
        """Test setting encryption key creates decryptor manager."""
        restorer = SnapshotRestorer("test_001")
        mock_decryptor = MagicMock()
        mock_decryptor_class.return_value = mock_decryptor
        
        key = b'test_key'
        restorer.set_encryption_key(key)
        
        assert restorer.encryption_manager is not None
        mock_decryptor_class.assert_called_once_with(key)

    @patch('builtins.open', new_callable=mock_open)
    @patch('toml.loads')
    @patch('RestoreUtility.SnapshotDecryptor')
    def test_load_snapshot_encrypted_happy_path(self, mock_decryptor_class, mock_toml, mock_file, temp_snapshot_file):
        """Test loading encrypted snapshot successfully."""
        file_path, encryption_key, expected_data = temp_snapshot_file
        mock_fernet = MagicMock()
        mock_decryptor = MagicMock()
        mock_decryptor.decrypt_data.return_value = str(expected_data)
        mock_decryptor_class.return_value = mock_decryptor
        mock_toml.return_value = expected_data
        
        restorer = SnapshotRestorer("test")
        restorer.set_encryption_key(encryption_key)
        result = restorer.load_snapshot(file_path)
        
        assert result == expected_data
        mock_file.assert_called_once_with(file_path, 'r', encoding='utf-8')

    @patch('builtins.open', new_callable=mock_open)
    @patch('toml.loads')
    def test_load_snapshot_unencrypted_happy_path(self, mock_toml, mock_file, temp_snapshot_file):
        """Test loading unencrypted snapshot successfully."""
        file_path, encryption_key, expected_data = temp_snapshot_file
        
        restorer = SnapshotRestorer("test")
        mock_file.return_value.read.return_value = str(expected_data)
        mock_toml.return_value = expected_data
        
        result = restorer.load_snapshot(file_path)
        
        assert result == expected_data

    @patch('builtins.open', new_callable=mock_open)
    def test_load_snapshot_file_not_found(self, mock_file):
        """Test loading snapshot when file doesn't exist."""
        mock_file.side_effect = FileNotFoundError("No such file")
        
        restorer = SnapshotRestorer("test")
        
        with pytest.raises(FileNotFoundError):
            restorer.load_snapshot("nonexistent.toml")

    @patch('builtins.open', new_callable=mock_open)
    @patch('toml.loads')
    def test_load_snapshot_decrypt_fail_raises_io(self, mock_toml, mock_file, encryption_key):
        """Test loading snapshot when decryption fails."""
        file_path = temp_snapshot_file[0]
        mock_toml.return_value = {'environment': {'TEST': 'value'}}
        
        restorer = SnapshotRestorer("test")
        restorer.set_encryption_key(encryption_key)
        mock_file.return_value.read.return_value = "encrypted_garbage"
        
        with pytest.raises(IOError) as exc_info:
            restorer.load_snapshot(file_path)
        assert "Decryption failed" in str(exc_info.value)

    @patch('os.environ.__setitem__')
    def test_restore_environment_variables_happy_path(self, mock_setitem):
        """Test restoring environment variables successfully."""
        restorer = SnapshotRestorer("test")
        snapshot_data = {
            'environment': {
                'VAR1': 'value1',
                'VAR2': 'value2'
            }
        }
        
        result = restorer.restore_environment_variables(snapshot_data)
        
        assert result == {'VAR1': 1, 'VAR2': 1}
        mock_setitem.assert_called()

    @patch('os.environ.__setitem__')
    def test_restore_environment_variables_with_integer_value(self, mock_setitem):
        """Test restoring environment variables with integer values."""
        restorer = SnapshotRestorer("test")
        snapshot_data = {
            'environment': {
                'PORT': 8080,
                'COUNT': 42
            }
        }
        
        result = restorer.restore_environment_variables(snapshot_data)
        
        assert result == {'PORT': 1, 'COUNT': 1}

    @patch('sys.stderr.write')
    @patch('os.environ.__setitem__', side_effect=PermissionError("No permission"))
    def test_restore_environment_variables_partial_failure(self, mock_setitem, mock_stderr):
        """Test restoring environment variables with some failures."""
        restorer = SnapshotRestorer("test")
        snapshot_data = {
            'environment': {
                'SUCCESS_VAR': 'value1',
                'FAIL_VAR': 'value2'
            }
        }
        
        result = restorer.restore_environment_variables(snapshot_data)
        
        assert result == {'SUCCESS_VAR': 1, 'FAIL_VAR': 0}
        mock_stderr.assert_called()

    @patch('psutil.process_iter')
    def test_verify_system_state_success(self, mock_iter):
        """Test system state verification with processes."""
        mock_process = MagicMock()
        mock_process.name.return_value = 'python3'
        mock_iter.return_value = [mock_process]
        
        restorer = SnapshotRestorer("test")
        result = restorer.verify_system_state()
        
        assert 'running_processes' in result
        assert len(result['running_processes']) == 1

    @patch('psutil.process_iter')
    def test_verify_system_state_no_processes(self, mock_iter):
        """Test system state verification with no processes."""
        mock_iter.return_value = []
        
        restorer = SnapshotRestorer("test")
        result = restorer.verify_system_state()
        
        assert 'running_processes' in result

    @patch('psutil.process_iter')
    def test_verify_system_state_with_exception(self, mock_iter):
        """Test system state verification with psutil exception."""
        mock_iter.side_effect = psutil.NoSuchProcess(pid=1234)
        
        restorer = SnapshotRestorer("test")
        result = restorer.verify_system_state()
        
        assert 'running_processes' in result
        assert result.get('status') == 'errors_detected'

    @patch('sys.stderr.write')
    def test_apply_system_configs_processes(self, mock_stderr):
        """Test applying system configurations."""
        restorer = SnapshotRestorer("test")
        snapshot_data = {
            'configs': [
                {'type': 'process', 'name': 'service1'},
                {'type': 'config', 'name': 'config1'}
            ]
        }
        
        result = restorer.apply_system_configs(snapshot_data)
        
        assert result == 2

    @patch('sys.stderr.write')
    def test_apply_system_configs_with_exception(self, mock_stderr):
        """Test applying configurations with failures."""
        restorer = SnapshotRestorer("test")
        snapshot_data = {
            'configs': [
                {'type': 'process', 'name': 'service1'},
                {'type': 'process', 'name': 'service2'}
            ]
        }
        
        result = restorer.apply_system_configs(snapshot_data)
        
        assert result == 2

    @patch('builtins.open', new_callable=mock_open)
    @patch('toml.loads')
    def test_restore_snapshot_missing_environment_key(self, mock_toml, mock_file, encryption_key):
        """Test restoration when snapshot lacks environment key."""
        file_path = temp_snapshot_file[0]
        mock_toml.return_value = {'configs': []}
        mock_file.return_value.read.return_value = str(mock_toml.return_value)
        
        restorer = SnapshotRestorer("test")
        restorer.set_encryption_key(encryption_key)
        
        result = restorer.restore_snapshot(file_path)
        
        assert result is False

    @patch('builtins.open', new_callable=mock_open)
    def test_restore_snapshot_file_not_found(self, mock_file, encryption_key):
        """Test restoration when snapshot file doesn't exist."""
        mock_file.side_effect = FileNotFoundError("File not found")
        
        restorer = SnapshotRestorer("test")
        restorer.set_encryption_key(encryption_key)
        
        result = restorer.restore_snapshot("missing_file.toml")
        
        assert result is False

    @patch('builtins.open', new_callable=mock_open)
    @patch('toml.loads')
    def test_restore_snapshot_full_success_path(self, mock_toml, mock_file, temp_snapshot_file, mock_env_vars, mock_psutil):
        """Test complete restoration success flow."""
        file_path, encryption_key, expected_data = temp_snapshot_file
        mock_decryptor = MagicMock()
        mock_decryptor.decrypt_data.return_value = str(expected_data)
        
        with patch('RestoreUtility.SnapshotDecryptor') as MockDecryptor:
            MockDecryptor.return_value = mock_decryptor
            
            restorer = SnapshotRestorer("test")
            restorer.set_encryption_key(encryption_key)
            
            result = restorer.restore_snapshot(file_path, encryption_key)
            
            assert result is True


class TestCLICommands:
    """Tests for CLI commands."""

    def test_restore_cli_group_exists(self):
        """Test CLI group is properly defined."""
        assert restore_cli is not None
        assert hasattr(restore_cli, 'commands')

    @patch('sys.exit')
    def test_restore_command_success(self, mock_exit, temp_snapshot_file):
        """Test restore command executes successfully."""
        file_path, encryption_key, _ = temp_snapshot_file
        
        with patch('click.get_current_context') as mock_ctx:
            with patch('click.invoke'):
                with patch('RestoreUtility.SnapshotRestorer') as MockRestorer:
                    mock_restorer = MagicMock()
                    mock_restorer.restore_snapshot.return_value = True
                    MockRestorer.return_value = mock_restorer
                    
                    ctx = mock_ctx.return_value
                    restore_command(ctx=ctx, snapshot_path=file_path, key=encryption_key)
                    
                    assert not mock_exit.called

    @patch('sys.exit')
    def test_restore_command_failure_exits(self, mock_exit, temp_snapshot_file):
        """Test restore command exits on failure."""
        file_path, encryption_key, _ = temp_snapshot_file
        
        with patch('click.get_current_context') as mock_ctx:
            with patch('click.invoke'):
                with patch('RestoreUtility.SnapshotRestorer') as MockRestorer:
                    mock_restorer = MagicMock()
                    mock_restorer.restore_snapshot.return_value = False
                    MockRestorer.return_value = mock_restorer
                    
                    ctx = mock_ctx.return_value
                    restore_command(ctx=ctx, snapshot_path=file_path, key=encryption_key)
                    
                    mock_exit.assert_called_with(1)

    @patch('sys.exit')
    def test_restore_command_file_not_found(self, mock_exit, temp_snapshot_file):
        """Test restore command handles missing file."""
        file_path, encryption_key, _ = temp_snapshot_file
        
        with patch('click.get_current_context') as mock_ctx:
            with patch('RestoreUtility.SnapshotRestorer') as MockRestorer:
                mock_restorer = MagicMock()
                mock_restorer.restore_snapshot.side_effect = FileNotFoundError("Not found")
                MockRestorer.return_value = mock_restorer
                
                ctx = mock_ctx.return_value
                restore_command(ctx=ctx, snapshot_path=file_path, key=encryption_key)
                
                mock_exit.assert_called_with(1)

    @patch('sys.exit')
    def test_verify_status_command_success(self, mock_exit):
        """Test verify status command executes successfully."""
        with patch('click.get_current_context') as mock_ctx:
            with patch('click.invoke'):
                with patch('RestoreUtility.SnapshotRestorer') as MockRestorer:
                    mock_restorer = MagicMock()
                    mock_restorer.verify_system_state.return_value = {'running_processes': ['python', 'bash']}
                    MockRestorer.return_value = mock_restorer
                    
                    ctx = mock_ctx.return_value
                    verify_status(ctx=ctx)
                    
                    assert not mock_exit.called

    @patch('sys.exit')
    def test_verify_status_command_failure(self, mock_exit):
        """Test verify status command on failure."""
        with patch('click.get_current_context') as mock_ctx:
            with patch('click.invoke'):
                with patch('RestoreUtility.SnapshotRestorer') as MockRestorer:
                    mock_restorer = MagicMock()
                    mock_restorer.verify_system_state.side_effect = Exception("Verify failed")
                    MockRestorer.return_value = mock_restorer
                    
                    ctx = mock_ctx.return_value
                    verify_status(ctx=ctx)
                    
                    mock_exit.assert_called_with(1)


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_decryptor_key_handling_variations(self, encryption_key):
        """Test decryptor with various key formats."""
        decryptor1 = SnapshotDecryptor(key=encryption_key)
        decryptor2 = SnapshotDecryptor(key=encryption_key)
        
        assert decryptor1.key == decryptor2.key

    def test_restorer_multiple_key_sets(self, encryption_key):
        """Test restorer with multiple encryption key changes."""
        restorer = SnapshotRestorer("test")
        restorer.set_encryption_key(encryption_key)
        
        new_key = Fernet.generate_key()
        restorer.set_encryption_key(new_key)
        
        assert restorer.encryption_manager.key == new_key

    def test_snapshot_data_missing_optional_fields(self, temp_snapshot_file, encryption_key):
        """Test snapshot with missing optional 'configs' field."""
        file_path, encryption_key, _ = temp_snapshot_file
        import toml
        from cryptography.fernet import Fernet
        
        minimal_data = {'environment': {'TEST': 'value'}}
        fernet = Fernet(encryption_key)
        encrypted = fernet.encrypt(str(minimal_data).encode('utf-8')).decode('utf-8')
        
        with tempfile.NamedTemporaryFile(suffix='.toml', delete=False) as f:
            f.write(encrypted.encode('utf-8'))
            temp_file = f.name
        
        try:
            restorer = SnapshotRestorer("test")
            restorer.set_encryption_key(encryption_key)
            result = restorer.load_snapshot(temp_file)
            assert result is not None
        finally:
            os.unlink(temp_file)

    def test_cli_key_option_not_provided(self, temp_snapshot_file, encryption_key):
        """Test CLI command without key option."""
        file_path, _, _ = temp_snapshot_file
        
        with patch('click.get_current_context') as mock_ctx:
            with patch('click.invoke'):
                with patch('RestoreUtility.SnapshotRestorer') as MockRestorer:
                    mock_restorer = MagicMock()
                    mock_restorer.restore_snapshot.return_value = True
                    MockRestorer.return_value = mock_restorer
                    
                    ctx = mock_ctx.return_value
                    restore_command(ctx=ctx, snapshot_path=file_path, key=None)
                    
                    assert mock_restorer.restore_snapshot.called

    def test_restore_snapshot_unencrypted_data(self, temp_snapshot_file):
        """Test restoration without encryption."""
        file_path, encryption_key, _ = temp_snapshot_file
        
        import toml
        from cryptography.fernet import Fernet
        
        unencrypted_data = {'environment': {'TEST': 'value'}, 'configs': []}
        with tempfile.NamedTemporaryFile(suffix='.toml', delete=False) as f:
            f.write(str(unencrypted_data).encode('utf-8'))
            temp_file = f.name
        
        try:
            restorer = SnapshotRestorer("test")
            # Don't set encryption key
            with patch('builtins.open', new_callable=mock_open) as mock_file:
                mock_file.return_value.read.return_value = str(unencrypted_data)
                with patch('toml.loads', return_value=unencrypted_data):
                    result = restorer.load_snapshot(temp_file)
                    assert result == unencrypted_data
        finally:
            os.unlink(temp_file)

    @patch('os.environ')
    @patch('os.environ.keys')
    def test_environment_variable_types_conversion(self, mock_keys, mock_environ):
        """Test restoration of different value types."""
        restorer = SnapshotRestorer("test")
        snapshot_data = {
            'environment': {
                'STRING_VAR': 'text_value',
                'INT_VAR': 123,
                'BOOL_VAR': True,
                'FLOAT_VAR': 3.14
            }
        }
        
        result = restorer.restore_environment_variables(snapshot_data)
        
        assert result == {'STRING_VAR': 1, 'INT_VAR': 1, 'BOOL_VAR': 1, 'FLOAT_VAR': 1}
        mock_environ.__setitem__.assert_called()

    def test_decryptor_invalid_key_handling(self, encryption_key):
        """Test decryptor handling of invalid operations."""
        decryptor = SnapshotDecryptor(key=encryption_key)
        
        # Test with empty string
        result = decryptor.encrypt_data('')
        assert result == decryptor.encrypt_data('').encode('utf-8').decode('utf-8')
        
        # Test with special characters
        special_data = 'test!@#$%^&*()_+-=[]{}|;:,.<>?'
        encrypted = decryptor.encrypt_data(special_data)
        decrypted = decryptor.decrypt_data(encrypted)
        assert decrypted == special_data


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])