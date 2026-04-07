import pytest
import unittest.mock as mock
import base64
import os
from pathlib import Path
from secure_payload import SecurePayload, Fernet, tomllib, toml, psutil, click, logger

# Fixtures for mocks
@pytest.fixture
def mock_fernet(monkeypatch):
    """Mock Fernet class for cryptography."""
    mock_fernet_instance = mock.MagicMock()
    mock_fernet_instance.encrypt.return_value = b"encrypted_bytes"
    mock_fernet_instance.decrypt.return_value = b"decrypted_value"

    monkeypatch.setattr("secure_payload.Fernet", mock.MagicMock(return_value=mock_fernet_instance))
    monkeypatch.setattr("secure_payload.Fernet.generate_key", mock.MagicMock(return_value=b"KEY" * 8))
    yield mock_fernet_instance

@pytest.fixture
def mock_pathlib(monkeypatch):
    """Mock Path methods to avoid real filesystem writes."""
    mock_path = mock.MagicMock(spec=Path)
    mock_path.exists.return_value = True
    mock_path.is_file.return_value = True
    
    # Simulate read_text returning valid TOML content
    mock_path.read_text.return_value = '{"data": {"key": "value"}}'
    
    monkeypatch.setattr("secure_payload.Path", mock.MagicMock(return_value=mock_path))
    yield mock_path

@pytest.fixture
def mock_psutil(monkeypatch):
    """Mock psutil for security context checks."""
    mock_process = mock.MagicMock()
    mock_process.pid = 12345
    mock_process.username.return_value = "testuser"
    
    monkeypatch.setattr("secure_payload.psutil.Process", mock.MagicMock(return_value=mock_process))
    monkeypatch.setattr("secure_payload.os", mock.MagicMock())
    monkeypatch.setattr("secure_payload.os.name", "posix")
    monkeypatch.setattr("secure_payload.os.getuid", mock.MagicMock(return_value=1000))
    yield mock_process

@pytest.fixture
def mock_click(monkeypatch):
    """Mock click for interactive prompts."""
    monkeypatch.setattr("secure_payload.click.prompt", mock.MagicMock(return_value="test_key"))
    yield

@pytest.fixture
def mock_toml(monkeypatch):
    """Mock TOML parsers."""
    mock_toml_instance = mock.MagicMock()
    mock_toml_instance.dumps.return_value = "data = { key = 'value' }"
    monkeypatch.setattr("secure_payload.toml", mock.MagicMock())
    monkeypatch.setattr("secure_payload.toml.loads", mock.MagicMock(return_value={"data": {"key": "value"}}))
    monkeypatch.setattr("secure_payload.tomllib", mock.MagicMock())
    monkeypatch.setattr("secure_payload.tomllib.loads", mock.MagicMock(return_value={"data": {"key": "value"}}))
    yield

# Test Cases for __init__
class TestSecurePayloadInit:
    def test_init_with_none_key(self, mock_fernet):
        """Test initialization with automatic key generation."""
        sp = SecurePayload()
        assert sp._fernet is not None
        assert sp.algorithm == "AES"
        assert sp._key is not None

    def test_init_with_valid_key(self, mock_fernet):
        """Test initialization with a provided 32-byte key."""
        key = b"01234567890123456789012345678901"  # 32 bytes
        sp = SecurePayload(key=key)
        assert sp._key == key
        assert sp._fernet is not None

    def test_init_with_invalid_key_length(self):
        """Test initialization with a key of wrong length."""
        key = b"short"  # Too short
        with pytest.raises(ValueError) as excinfo:
            SecurePayload(key=key)
        assert "32 bytes" in str(excinfo.value)

    def test_init_with_invalid_key_type(self):
        """Test initialization with a key that is not bytes."""
        with pytest.raises(ValueError):
            SecurePayload(key="not_bytes")

# Test Cases for encrypt_data
class TestSecurePayloadEncrypt:
    def test_encrypt_single_sensitive_key(self, mock_fernet):
        """Test encryption of a single sensitive field."""
        sp = SecurePayload()
        data = {"password": "secret123", "user": "alice"}
        result = sp.encrypt_data(data, ["password"])
        assert "password" in result
        assert result["password"] is not None
        assert "password__metadata" in result
        assert result["password__metadata"]["encrypted"] is True

    def test_encrypt_nested_sensitive_key(self, mock_fernet):
        """Test encryption of sensitive fields inside nested dictionaries."""
        sp = SecurePayload()
        data = {"profile": {"password": "secret123", "name": "alice"}, "token": "abc"}
        result = sp.encrypt_data(data, ["password"])
        assert result["profile"]["password"] is not None
        assert "profile__metadata" not in result
        # Metadata should be at the key level relative to the sensitive data
        assert result["profile"]["password__metadata"] is not None

    def test_encrypt_non_dict_input(self):
        """Test that non-dict input raises TypeError."""
        sp = SecurePayload()
        with pytest.raises(TypeError):
            sp.encrypt_data("not a dict", ["key"])

    def test_encrypt_no_matching_keys(self, mock_fernet):
        """Test when no keys match sensitive_keys."""
        sp = SecurePayload()
        data = {"name": "alice", "age": 25}
        result = sp.encrypt_data(data, ["password", "secret"])
        # Values should remain as-is, no metadata added
        assert result["name"] == "alice"

# Test Cases for decrypt_data
class TestSecurePayloadDecrypt:
    def test_decrypt_valid_data(self, mock_fernet):
        """Test successful decryption of encrypted data."""
        sp = SecurePayload()
        # Prepare payload similar to what encrypt_data produces
        encrypted_key = "FgAAAAA_encrypted_bytes"  # Mocked Fernet base64 starting with 'F' and 'g'
        payload = {
            "password": encrypted_key,
            "password__metadata": {"encrypted": True},
            "user": "alice"
        }
        # Mock decrypt return value decoding
        mock_fernet_instance = sp._fernet
        mock_fernet_instance.decrypt.return_value = b"original_secret"
        
        result = sp.decrypt_data(payload, ["password"])
        assert result["password"] == "original_secret"
        # Metadata cleaned up
        assert result["password__metadata"] is None

    def test_decrypt_skip_non_sensitive(self, mock_fernet):
        """Test that non-sensitive keys are left unchanged."""
        sp = SecurePayload()
        payload = {"user": "alice"}
        result = sp.decrypt_data(payload, ["password"])
        assert result["user"] == "alice"

    def test_decrypt_invalid_signature(self, mock_fernet):
        """Test handling of InvalidSignature exception."""
        sp = SecurePayload()
        from cryptography.exceptions import InvalidSignature
        mock_fernet_instance = sp._fernet
        mock_fernet_instance.decrypt.side_effect = InvalidSignature("Bad Signature")
        
        payload = {
            "password": "gAAAAAInvalid",
            "password__metadata": {"encrypted": True}
        }
        result = sp.decrypt_data(payload, ["password"])
        # Value should remain as provided if decryption fails
        assert result["password"] == "gAAAAAInvalid"

    def test_decrypt_invalid_data_type(self):
        """Test input validation for non-dict payload."""
        sp = SecurePayload()
        with pytest.raises(TypeError):
            sp.decrypt_data("not a dict", ["key"])

# Test Cases for key management
class TestSecurePayloadKeyManagement:
    def test_generate_and_save_key(self, mock_pathlib):
        """Test key generation and file saving."""
        sp = SecurePayload()
        key, success = sp.generate_and_save_key("test_key.bin")
        assert success is True
        assert key is not None
        assert mock_pathlib.write_bytes.called

    def test_generate_and_save_key_failure(self, mock_pathlib, monkeypatch):
        """Test key generation failure path."""
        monkeypatch.setattr("secure_payload.Path.write_bytes", mock.MagicMock(side_effect=IOError))
        sp = SecurePayload()
        key, success = sp.generate_and_save_key("fail_key.bin")
        assert success is False

    def test_load_key_success(self, mock_pathlib):
        """Test loading a valid key."""
        sp = SecurePayload()
        mock_pathlib.read_bytes.return_value = b"key_bytes"
        key = sp.load_key("test_key.bin")
        assert key == b"key_bytes"
        assert mock_pathlib.read_bytes.called

    def test_load_key_file_not_found(self, mock_pathlib, monkeypatch):
        """Test loading key when file does not exist."""
        monkeypatch.setattr("secure_payload.Path.exists", mock.MagicMock(return_value=False))
        sp = SecurePayload()
        with pytest.raises(FileNotFoundError):
            sp.load_key("missing_key.bin")

# Test Cases for Security Context
class TestSecurePayloadSecurity:
    def test_get_security_context_success(self, mock_psutil):
        """Test gathering security context successfully."""
        sp = SecurePayload()
        ctx = sp.get_security_context()
        assert "pid" in ctx
        assert ctx["pid"] == 12345
        assert "username" in ctx

    def test_get_security_context_root_risk(self, mock_psutil, monkeypatch):
        """Test context flags for root user."""
        monkeypatch.setattr("secure_payload.os.getuid", mock.MagicMock(return_value=0))
        sp = SecurePayload()
        ctx = sp.get_security_context()
        assert ctx["running_as_root"] is True
        assert ctx["security_flag"] == "medium_risk"

    def test_get_security_context_error(self, mock_psutil, monkeypatch):
        """Test context gathering error handling."""
        monkeypatch.setattr("secure_payload.psutil.Process", mock.MagicMock(side_effect=Exception("Access Denied")))
        sp = SecurePayload()
        ctx = sp.get_security_context()
        assert "error" in ctx

# Test Cases for Snapshot Serialization
class TestSecurePayloadSnapshot:
    def test_dump_snapshot_to_toml(self, mock_pathlib, mock_toml, mock_psutil):
        """Test saving snapshot to TOML file."""
        sp = SecurePayload()
        data = {"data": "snapshot"}
        success = sp.dump_snapshot_to_toml(data, "snapshot.toml")
        assert success is True
        assert mock_pathlib.write_text.called

    def test_dump_snapshot_to_toml_failure(self, mock_pathlib, monkeypatch):
        """Test save failure."""
        monkeypatch.setattr("secure_payload.Path.write_text", mock.MagicMock(side_effect=IOError))
        sp = SecurePayload()
        success = sp.dump_snapshot_to_toml({}, "fail.toml")
        assert success is False

    def test_load_snapshot_from_toml(self, mock_pathlib, mock_toml):
        """Test loading snapshot from TOML file."""
        sp = SecurePayload()
        # Setup mock to return specific content
        mock_pathlib.read_text.return_value = '{"data": {"key": "val"}}'
        result = sp.load_snapshot_from_toml("snapshot.toml")
        assert result["key"] == "val"

    def test_load_snapshot_from_toml_not_found(self, mock_pathlib, monkeypatch):
        """Test loading from missing file."""
        monkeypatch.setattr("secure_payload.Path.exists", mock.MagicMock(return_value=False))
        sp = SecurePayload()
        with pytest.raises(FileNotFoundError):
            sp.load_snapshot_from_toml("missing.toml")

# Test Cases for CLI Helper
class TestSecurePayloadCli:
    def test_prompt_for_key_load(self, mock_psutil, mock_pathlib, mock_pathlib, monkeypatch):
        """Test loading key from path."""
        sp = SecurePayload()
        mock_pathlib.read_bytes.return_value = b"key_bytes"
        key = sp.prompt_for_key(key_path="existing.key", generate_new=False)
        assert key == b"key_bytes"

    def test_prompt_for_key_generate(self, mock_psutil, mock_pathlib, mock_pathlib, monkeypatch):
        """Test generating a new key."""
        monkeypatch.setattr("secure_payload.click.prompt", mock.MagicMock(side_effect=[
            "path_to_new_key.key", 
            "password",
            "password"
        ]))
        sp = SecurePayload()
        key = sp.prompt_for_key(generate_new=True)
        # Should return generated key, file operations mocked in fixture
        assert key is not None or False # Depends on mock success, usually None if mocked fail
            
    def test_prompt_for_key_invalid_password(self, mock_psutil, mock_pathlib, monkeypatch):
        """Test key prompt with invalid format."""
        monkeypatch.setattr("secure_payload.click.prompt", mock.MagicMock(side_effect=["invalid"]))
        monkeypatch.setattr("secure_payload.base64.b64decode", mock.MagicMock(side_effect=ValueError))
        sp = SecurePayload()
        key = sp.prompt_for_key()
        assert key is None

    def test_prompt_for_key_load_fail(self, mock_psutil, mock_pathlib, monkeypatch):
        """Test key prompt when load fails."""
        monkeypatch.setattr("secure_payload.click.prompt", mock.MagicMock(return_value="test"))
        monkeypatch.setattr("secure_payload.Path", mock.MagicMock(side_effect=FileNotFoundError))
        sp = SecurePayload()
        key = sp.prompt_for_key(key_path="bad.key")
        assert key is None