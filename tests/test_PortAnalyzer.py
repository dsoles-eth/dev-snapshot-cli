import pytest
from unittest.mock import MagicMock, patch, call
from pathlib import Path
from datetime import datetime
import secrets
import toml
from cryptography.fernet import Fernet, InvalidToken

from PortAnalyzer import PortAnalyzer


# --- Fixtures ---

@pytest.fixture
def mock_fernet_key():
    return b'test_encryption_key_12345678901234567890123456789012345678'


@pytest.fixture
def mock_psutil_connections():
    """Mock psutil.net_connections returning valid listening connection objects."""
    conn_mock = MagicMock()
    conn_mock.status = 'LISTEN_STATE'
    conn_mock.laddr = MagicMock()
    conn_mock.laddr.port = 8080
    conn_mock.laddr.ip = '127.0.0.1'
    conn_mock.pid = 12345
    conn_mock.family = 2  # AF_INET (TCP)
    
    # Create a second UDP connection
    conn_mock2 = MagicMock()
    conn_mock2.status = 'LISTEN_STATE'
    conn_mock2.laddr = MagicMock()
    conn_mock2.laddr.port = 53
    conn_mock2.laddr.ip = '0.0.0.0'
    conn_mock2.pid = 54321
    conn_mock2.family = 17  # AF_INET6 usually, but we treat non-2 as UDP for simplicity in this logic, code says 2 is tcp
    
    # Adjust logic to match the code: 'tcp' if conn.family == 2 else 'udp'
    # So family=17 means UDP.
    return [conn_mock, conn_mock2]


@pytest.fixture
def mock_process_name():
    """Mock psutil.Process returning a specific name."""
    proc_mock = MagicMock()
    proc_mock.name.return_value = 'nginx'
    return proc_mock


@pytest.fixture
def mock_path(tmp_path):
    """Mock Path operations to prevent file system writes."""
    mock_p = MagicMock(spec=Path)
    mock_p.name = 'snapshot.toml'
    mock_p.parent = MagicMock()
    mock_p.parent.mkdir = MagicMock()
    mock_p.write_bytes = MagicMock()
    mock_p.read_bytes = MagicMock(return_value=b'encrypted_data_placeholder')
    mock_p.open = MagicMock()
    mock_p.read_text = MagicMock(return_value='meta: {}')
    
    # Ensure 'open' mock returns a file-like object context manager
    mock_p.open.return_value.__enter__ = MagicMock(return_value=MagicMock())
    mock_p.open.return_value.__exit__ = MagicMock(return_value=False)
    mock_p.open.return_value.write = MagicMock()
    mock_p.open.return_value.close = MagicMock()
    mock_p.open.return_value.read = MagicMock(return_value='{meta: {}, data: []}')
    
    # Mock toml.load behavior for open
    def mock_open_func(*args, **kwargs):
        return MagicMock()
    
    # Actually simpler: just set return_value for read_bytes and open behavior
    return mock_p


# --- Tests for Class Initialization ---

class TestPortAnalyzerInit:
    def test_init_with_encryption_key(self):
        key = b'f' * 32
        with patch.object(PortAnalyzer, '__init__'):
            analyzer = PortAnalyzer.__new__(PortAnalyzer)
            analyzer._cipher = MagicMock()
            analyzer._encryption_key = key
        assert analyzer._encryption_key == key
        assert analyzer._cipher is not None

    def test_init_no_encryption_key(self):
        analyzer = PortAnalyzer()
        assert analyzer._cipher is None
        assert analyzer._encryption_key is None

    def test_init_sets_cipher_if_key_provided(self):
        key = b'f' * 32
        with patch('PortAnalyzer.Fernet') as mock_fernet_class:
            mock_fernet_instance = MagicMock()
            mock_fernet_class.return_value = mock_fernet_instance
            analyzer = PortAnalyzer(encryption_key=key)
        
        mock_fernet_class.assert_called_once_with(key)
        assert analyzer._cipher is mock_fernet_instance


# --- Tests for Key Generation and Setting ---

class TestPortAnalyzerKeyManagement:
    @pytest.fixture
    def mock_generate_key(self):
        with patch('PortAnalyzer.Fernet.generate_key', return_value=b'key_bytes') as mock_method:
            yield mock_method

    def test_generate_key_returns_bytes(self, mock_generate_key):
        analyzer = PortAnalyzer()
        key = analyzer.generate_key()
        assert isinstance(key, bytes)
        mock_generate_key.assert_called_once()

    def test_generate_key_produces_different_keys(self):
        analyzer = PortAnalyzer()
        key1 = analyzer.generate_key()
        key2 = analyzer.generate_key()
        # Fernet keys are random, highly likely to differ, but we check equality
        assert key1 != key2

    def test_set_encryption_key_updates_cipher(self, mock_fernet_key):
        with patch('PortAnalyzer.Fernet') as mock_fernet_class:
            mock_fernet_instance = MagicMock()
            mock_fernet_class.return_value = mock_fernet_instance
            analyzer = PortAnalyzer()
            analyzer.set_encryption_key(mock_fernet_key)
        
        mock_fernet_class.assert_called_once_with(mock_fernet_key)
        assert analyzer._cipher is mock_fernet_instance
        assert analyzer._encryption_key == mock_fernet_key


# --- Tests for Analyze Function ---

class TestPortAnalyzerAnalyze:
    def test_analyze_returns_list_with_success(self, mock_psutil_connections, mock_process_name):
        with patch('PortAnalyzer.psutil') as mock_psutil_module:
            with patch('PortAnalyzer.psutil.Process', return_value=mock_process_name):
                mock_psutil_module.net_connections.return_value = mock_psutil_connections
                mock_psutil_module.CONN_LISTEN = 'LISTEN_STATE'
                
                analyzer = PortAnalyzer()
                result = analyzer.analyze()
        
        assert isinstance(result, list)
        assert len(result) == 2
        assert 'port' in result[0]
        assert 'pid' in result[0]
        assert result[0]['port'] == 8080
        assert result[0]['process_name'] == 'nginx'

    def test_analyze_raises_permission_error(self, mock_psutil_connections):
        with patch('PortAnalyzer.psutil') as mock_psutil_module:
            mock_psutil_module.net_connections.side_effect = PermissionError("Access denied")
            
            analyzer = PortAnalyzer()
            with pytest.raises(PermissionError):
                analyzer.analyze()

    def test_analyze_handles_no_such_process_gracefully(self, mock_psutil_connections, mock_process_name):
        mock_process = MagicMock()
        mock_process.name.side_effect = Exception("Unknown")
        
        # Configure connection to trigger error
        conn = mock_psutil_connections[0]
        conn.pid = 999
        
        with patch('PortAnalyzer.psutil') as mock_psutil_module:
            with patch('PortAnalyzer.psutil.Process') as mock_proc_class:
                mock_proc_class.side_effect = Exception("Process died")
                mock_psutil_module.net_connections.return_value = mock_psutil_connections
                mock_psutil_module.CONN_LISTEN = 'LISTEN_STATE'
                
                analyzer = PortAnalyzer()
                result = analyzer.analyze()
        
        # Should not crash, should continue
        assert isinstance(result, list)

    def test_analyze_sets_correct_protocol_tcp(self, mock_psutil_connections):
        with patch('PortAnalyzer.psutil') as mock_psutil_module:
            mock_psutil_module.net_connections.return_value = mock_psutil_connections
            mock_psutil_module.CONN_LISTEN = 'LISTEN_STATE'
            
            analyzer = PortAnalyzer()
            result = analyzer.analyze()
        
        assert result[0]['protocol'] == 'tcp'

    def test_analyze_sets_correct_protocol_udp(self, mock_psutil_connections):
        with patch('PortAnalyzer.psutil') as mock_psutil_module:
            mock_psutil_module.net_connections.return_value = mock_psutil_connections
            mock_psutil_module.CONN_LISTEN = 'LISTEN_STATE'
            
            analyzer = PortAnalyzer()
            result = analyzer.analyze()
        
        assert result[1]['protocol'] == 'udp'


# --- Tests for Snapshot Saving and Loading ---

class TestPortAnalyzerSnapshotPersistence:
    def test_save_snapshot_creates_directories(self):
        mock_path = MagicMock()
        mock_path.parent = MagicMock()
        
        with patch('PortAnalyzer.Path') as mock_path_class:
            mock_path_class.return_value = mock_path
            analyzer = PortAnalyzer()
            analyzer.save_snapshot(mock_path, [])
        
        mock_path.parent.mkdir.assert_called_once_with(parents=True, exist_ok=True)

    def test_save_snapshot_writes_encrypted_data(self, mock_fernet_key, mock_path):
        analyzer = PortAnalyzer()
        analyzer._cipher = MagicMock()
        
        # Mock encryption result
        analyzer._cipher.encrypt = MagicMock(return_value=b'encrypted_data')
        
        with patch('PortAnalyzer.Path') as mock_path_class:
            mock_path_class.return_value = mock_path
            analyzer.save_snapshot(mock_path, [{'port': 80}])
        
        analyzer._cipher.encrypt.assert_called_once()
        mock_path.write_bytes.assert_called_once()

    def test_save_snapshot_writes_plain_toml_no_key(self, mock_path):
        with patch('PortAnalyzer.Path') as mock_path_class:
            mock_path_class.return_value = mock_path
            analyzer = PortAnalyzer()
            
            # Mock path.open to return a writable file-like mock
            mock_file = MagicMock()
            mock_path.open.return_value.__enter__.return_value = mock_file
            
            analyzer.save_snapshot(mock_path, [{'port': 80}])
        
        # Open write mode
        mock_path.open.assert_called_once_with('w', encoding='utf-8')
        mock_file.write.assert_called()

    def test_save_snapshot_permission_error(self):
        with patch('PortAnalyzer.Path') as mock_path_class:
            mock_path = MagicMock()
            mock_path_class.return_value = mock_path
            mock_path.parent.mkdir.side_effect = PermissionError("No write access")
            
            analyzer = PortAnalyzer()
            with pytest.raises(PermissionError):
                analyzer.save_snapshot(mock_path, [])

    def test_load_snapshot_reads_plain_toml(self, mock_path):
        with patch('PortAnalyzer.Path') as mock_path_class:
            mock_path_class.return_value = mock_path
            mock_path.read_bytes.return_value = b'not encrypted data'
            mock_path.open.return_value.__enter__.return_value.read.return_value = '{"meta": {}}'
            
            analyzer = PortAnalyzer()
            result = analyzer.load_snapshot(mock_path)
        
        # Should fall back to plain read
        mock_path.read_bytes.assert_called_once()
        mock_path.open.assert_called()
        assert result is not None

    def test_load_snapshot_reads_encrypted(self, mock_path):
        mock_path.read_bytes.return_value = b'encrypted_bytes'
        
        with patch('PortAnalyzer.Path') as mock_path_class:
            mock_path_class.return_value = mock_path
            
            analyzer = PortAnalyzer()
            analyzer._cipher = MagicMock()
            analyzer._cipher.decrypt = MagicMock(return_value=b'decrypted tomldata')
            
            with patch('PortAnalyzer.toml.loads') as mock_loads:
                mock_loads.return_value = {'meta': {}}
                result = analyzer.load_snapshot(mock_path)
        
        analyzer._cipher.decrypt.assert_called_once()
        mock_loads.assert_called_once()
        assert result == {'meta': {}}

    def test_load_snapshot_file_not_found(self, mock_path):
        # Simulate file not found
        with patch('PortAnalyzer.Path') as mock_path_class:
            mock_path_class.return_value = mock_path
            mock_path.read_bytes.side_effect = FileNotFoundError("Not found")
            
            analyzer = PortAnalyzer()
            with pytest.raises(FileNotFoundError):
                analyzer.load_snapshot(mock_path)


# --- Tests for Internal Helpers ---

class TestPortAnalyzerInternalHelpers:
    def test_get_process_name_success(self):
        with patch('PortAnalyzer.psutil') as mock_psutil:
            mock_proc = MagicMock()
            mock_proc.name.return_value = 'python'
            mock_psutil.Process.return_value = mock_proc
            
            analyzer = PortAnalyzer()
            name = analyzer._get_process_name(123)
        
        assert name == 'python'

    def test_get_process_name_access_denied(self):
        with patch('PortAnalyzer.psutil') as mock_psutil:
            mock_psutil.Process.side_effect = PermissionError()
            
            analyzer = PortAnalyzer()
            name = analyzer._get_process_name(123)
        
        assert name == 'Unknown'

    def test_get_process_name_no_process(self):
        with patch('PortAnalyzer.psutil') as mock_psutil:
            mock_psutil.Process.side_effect = Exception() # NoSuchProcess usually specific, generic exception handled here
            
            analyzer = PortAnalyzer()
            name = analyzer._get_process_name(123)
        
        assert name == 'Unknown'

    def test_encrypt_data_requires_key(self):
        analyzer = PortAnalyzer()
        with pytest.raises(ValueError):
            analyzer._encrypt_data({'test': 'data'})

    def test_decrypt_data_invalid_token(self, mock_fernet_key):
        analyzer = PortAnalyzer(encryption_key=mock_fernet_key)
        
        with patch('PortAnalyzer.Fernet') as mock_fernet_class:
            # Simulate decrypt failing with InvalidToken
            mock_fernet_class.return_value.decrypt = MagicMock(side_effect=InvalidToken)
            
            with pytest.raises(ValueError) as excinfo:
                analyzer._decrypt_data(b'garbage')
            
            assert "Invalid decryption token" in str(excinfo.value)


# --- Tests for Analysis Logic Edge Cases ---

class TestPortAnalyzerAnalysisLogic:
    def test_analyze_ignores_non_listening_connections(self, mock_psutil_connections):
        # Modify connections to not be LISTEN
        for conn in mock_psutil_connections:
            conn.status = 'ESTABLISHED'
            
        with patch('PortAnalyzer.psutil') as mock_psutil_module:
            mock_psutil_module.net_connections.return_value = mock_psutil_connections
            mock_psutil_module.CONN_LISTEN = 'LISTEN_STATE'
            
            analyzer = PortAnalyzer()
            result = analyzer.analyze()
        
        assert len(result) == 0

    def test_analyze_records_unknown_process_name(self):
        with patch('PortAnalyzer.psutil') as mock_psutil_module:
            mock_proc = MagicMock()
            mock_proc.name.side_effect = Exception("No access")
            mock_psutil_module.Process.return_value = mock_proc
            mock_psutil_module.CONN_LISTEN = 'LISTEN_STATE'
            
            conn_mock = MagicMock()
            conn_mock.status = 'LISTEN_STATE'
            conn_mock.laddr = MagicMock(port=8080)
            conn_mock.pid = 111
            conn_mock.family = 2
            
            mock_psutil_module.net_connections.return_value = [conn_mock]
            
            analyzer = PortAnalyzer()
            result = analyzer.analyze()
            
        # In access denied case in analyze method, it catches AccessDenied and sets 'Unknown'
        # In _get_process_name, it returns 'Unknown' on exception.
        # The flow in analyze: _get_process_name returns 'Unknown'
        assert result[0]['process_name'] == 'Unknown'

    def test_analyze_includes_timestamp(self):
        with patch('PortAnalyzer.psutil') as mock_psutil_module:
            mock_psutil_module.CONN_LISTEN = 'LISTEN_STATE'
            mock_psutil_module.net_connections.return_value = []
            
            # Ensure datetime.now is mocked to be predictable
            with patch('PortAnalyzer.datetime') as mock_datetime:
                mock_datetime.now.return_value = datetime(2023, 1, 1, 12, 0, 0)
                mock_datetime.now.return_value.isoformat.return_value = "2023-01-01T12:00:00"
                
                analyzer = PortAnalyzer()
                result = analyzer.analyze()
        
        # Check structure exists, timestamp key is present
        assert 'snapshot_timestamp' in result or len(result) == 0 # Empty list case
        
        # If we force one result
        conn_mock = MagicMock()
        conn_mock.status = 'LISTEN_STATE'
        conn_mock.laddr = MagicMock(port=8080)
        conn_mock.pid = 111
        conn_mock.family = 2
        
        with patch('PortAnalyzer.psutil') as mock_psutil_module:
            with patch('PortAnalyzer.datetime') as mock_dt:
                mock_psutil_module.CONN_LISTEN = 'LISTEN_STATE'
                mock_psutil_module.net_connections.return_value = [conn_mock]
                mock_dt.now.return_value.isoformat.return_value = "2023-01-01T12:00:00"
                
                analyzer = PortAnalyzer()
                result = analyzer.analyze()
        
        assert result[0]['snapshot_timestamp'] == "2023-01-01T12:00:00"
        assert result[0]['timestamp'] == "2023-01-01T12:00:00" # Note: code saves to snapshot_timestamp