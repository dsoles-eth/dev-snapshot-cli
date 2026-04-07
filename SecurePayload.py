from typing import Any, Dict, List, Optional, Union, Tuple
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
import cryptography
import tomllib
import toml
import click
import psutil
import os
import base64
import hashlib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class SecurePayload:
    """
    Manages secure encryption and decryption of sensitive data within snapshots.
    Handles key management and integration with TOML serialization formats.
    """

    def __init__(self, key: Optional[bytes] = None, algorithm: str = "AES"):
        """
        Initialize the SecurePayload manager.

        Args:
            key: An optional 32-byte URL-safe base64-encoded Fernet key.
                If None, a new key will be generated automatically.
            algorithm: The encryption algorithm to use. Defaults to "AES".
                Currently only AES via Fernet is supported.

        Raises:
            ValueError: If the provided key is invalid or the wrong length.
            ImportError: If the cryptography package is missing.
        """
        self.algorithm = algorithm
        self._key = None
        self._fernet = None

        try:
            if key is not None:
                if not isinstance(key, bytes):
                    raise ValueError("Key must be bytes.")
                if len(key) != 32:
                    raise ValueError("Key must be exactly 32 bytes long.")
                self._key = key
            else:
                self._key = Fernet.generate_key()
            
            self._fernet = Fernet(self._key)
            logger.info("SecurePayload initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize SecurePayload: {e}")
            raise ValueError(f"Failed to initialize SecurePayload: {e}") from e

    def encrypt_data(self, data: Dict[str, Any], sensitive_keys: List[str]) -> bytes:
        """
        Encrypt specific fields in a dictionary payload.

        This function recursively traverses the dictionary. Any key found in the
        `sensitive_keys` list will have its value encrypted using Fernet.
        All other values are passed through as-is or converted to JSON serializable format.

        Args:
            data: The dictionary containing the snapshot data.
            sensitive_keys: A list of strings representing keys that contain sensitive data.

        Returns:
            A dictionary with sensitive values encrypted and ready for storage.
            The returned structure contains 'encrypted_data' (base64 string) and 'metadata'.
        """
        try:
            if not isinstance(data, dict):
                raise TypeError("Input data must be a dictionary.")

            encrypted_payload = data.copy()
            for key, value in data.items():
                if key in sensitive_keys or self._is_value_in_list(key, sensitive_keys):
                    original_value = value
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value)
                    
                    # Encrypt the value
                    encrypted_bytes = self._fernet.encrypt(value.encode('utf-8'))
                    encrypted_payload[key] = base64.b64encode(encrypted_bytes).decode('utf-8')
                    encrypted_payload[f"{key}__metadata"] = {
                        "encrypted": True,
                        "method": self.algorithm,
                        "timestamp": str(os.getpid()) # Simple context marker
                    }
                    logger.debug(f"Encrypted field: {key}")
                elif isinstance(value, dict):
                    # Recurse into nested dictionaries
                    encrypted_payload[key] = self.encrypt_data(value, sensitive_keys)

            return encrypted_payload
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise RuntimeError(f"Encryption failed: {e}") from e

    def decrypt_data(self, encrypted_payload: Dict[str, Any], sensitive_keys: List[str]) -> Dict[str, Any]:
        """
        Decrypt specific fields in a dictionary payload.

        Args:
            encrypted_payload: The dictionary containing encrypted data.
            sensitive_keys: A list of strings representing keys that contain encrypted data.

        Returns:
            The decrypted dictionary with original values restored.
        """
        try:
            if not isinstance(encrypted_payload, dict):
                raise TypeError("Encrypted payload must be a dictionary.")

            decrypted_payload = encrypted_payload.copy()
            for key, value in encrypted_payload.items():
                if key in sensitive_keys or self._is_value_in_list(key, sensitive_keys):
                    try:
                        # Try to retrieve metadata to confirm encryption status
                        metadata_key = f"{key}__metadata"
                        if metadata_key in decrypted_payload:
                            metadata = decrypted_payload[metadata_key]
                            if not metadata.get("encrypted", False):
                                continue
                        
                        if isinstance(value, str) and value.startswith("F"):
                            # Fernet signatures often start with standard chars, 
                            # assuming base64 encoding in our storage format:
                            if value.startswith("gAAAAA"):
                                raw_bytes = base64.b64decode(value.encode('utf-8'))
                            else:
                                # Fernet encrypted bytes base64 usually starts with specific char
                                raw_bytes = base64.b64decode(value.encode('utf-8'))

                            decrypted_value = self._fernet.decrypt(raw_bytes)
                            decrypted_payload[key] = decrypted_value.decode('utf-8')
                            decrypted_payload[metadata_key] = None # Clean up metadata
                        elif isinstance(value, (dict, list)):
                            decrypted_payload[key] = self.decrypt_data(value, sensitive_keys)
                    except (InvalidSignature, Exception) as e:
                        logger.warning(f"Decryption warning for key '{key}': {e}")
                        decrypted_payload[key] = value # Keep original if decryption fails
                    except Exception as e:
                        logger.error(f"Failed to decrypt key '{key}': {e}")
                        raise

            return decrypted_payload
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise RuntimeError(f"Decryption failed: {e}") from e

    def _is_value_in_list(self, value: str, sensitive_keys: List[str]) -> bool:
        """Helper to check partial matching for nested keys."""
        for key in sensitive_keys:
            if key in value or value.endswith(key):
                return True
        return False

    def generate_and_save_key(self, file_path: Union[str, Path]) -> Tuple[bytes, bool]:
        """
        Generate a new encryption key and save it securely.

        Args:
            file_path: Path to the file where the key will be stored.

        Returns:
            A tuple containing the generated key and a boolean indicating success.
        """
        try:
            key = Fernet.generate_key()
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(key)
            # Secure file permissions if on POSIX
            if os.name != 'nt':
                os.chmod(path, 0o600)
            logger.info(f"Encryption key saved to {file_path}")
            return key, True
        except Exception as e:
            logger.error(f"Failed to save key to {file_path}: {e}")
            return key, False

    def load_key(self, file_path: Union[str, Path]) -> bytes:
        """
        Load an encryption key from a file.

        Args:
            file_path: Path to the file containing the key.

        Returns:
            The loaded key bytes.
        """
        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"Key file not found: {file_path}")
            if not path.is_file():
                raise ValueError(f"Key path is not a file: {file_path}")
            return path.read_bytes()
        except Exception as e:
            logger.error(f"Failed to load key from {file_path}: {e}")
            raise RuntimeError(f"Key loading failed: {e}") from e

    def get_security_context(self) -> Dict[str, Any]:
        """
        Gather security context information about the running process.
        Uses psutil to ensure environment safety.

        Returns:
            A dictionary containing process UID, GID, and security flags.
        """
        try:
            current_process = psutil.Process()
            pid = current_process.pid
            username = current_process.username()
            # Check if running as root/sudo which might be a security risk for storing keys
            is_root = (os.getuid() == 0) if os.name != 'nt' else False
            
            return {
                "pid": pid,
                "username": username,
                "running_as_root": is_root,
                "security_flag": "low_risk" if not is_root else "medium_risk"
            }
        except Exception as e:
            logger.warning(f"Could not determine security context: {e}")
            return {"pid": os.getpid(), "error": str(e)}

    def dump_snapshot_to_toml(self, data: Dict[str, Any], file_path: Union[str, Path]) -> bool:
        """
        Serialize the snapshot payload to a TOML file for storage.

        Args:
            data: The (encrypted or raw) dictionary payload.
            file_path: Path to the TOML file to write.

        Returns:
            Boolean indicating success.
        """
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            # Add a header with context info for debugging if needed
            context_info = self.get_security_context()
            metadata = {
                "snapshot_metadata": {
                    "generated_at": "TOML_GENERATED",
                    "security_context": context_info,
                    "schema_version": "1.0"
                },
                "data": data
            }

            # Serialize to TOML
            toml_content = toml.dumps(metadata)
            path.write_text(toml_content)
            return True
        except Exception as e:
            logger.error(f"Failed to write TOML snapshot: {e}")
            return False

    def load_snapshot_from_toml(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Load a snapshot payload from a TOML file.

        Args:
            file_path: Path to the TOML file to read.

        Returns:
            The dictionary payload extracted from the file.
        """
        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            content = path.read_text()
            # Handle both old and new toml parser
            try:
                # Attempt toml library (Python 3.11+)
                parsed = tomllib.loads(content)
            except ImportError:
                # Fallback for older python versions with toml package
                parsed = toml.loads(content)

            return parsed.get("data", parsed)
        except Exception as e:
            logger.error(f"Failed to load snapshot from TOML: {e}")
            raise RuntimeError(f"Snapshot load failed: {e}") from e

    def prompt_for_key(self, key_path: Optional[Union[str, Path]] = None, generate_new: bool = False) -> Optional[bytes]:
        """
        Interactive CLI helper to retrieve the encryption key.

        Args:
            key_path: Optional path to load an existing key file.
            generate_new: If True, ask user to create a new key file.

        Returns:
            The encryption key bytes or None if cancelled/failed.
        """
        try:
            if key_path and generate_new:
                raise ValueError("Cannot load from path and generate new key simultaneously.")
            
            if key_path:
                try:
                    return self.load_key(key_path)
                except Exception:
                    click.echo(f"Failed to load key from {key_path}.", err=True)
            
            if generate_new:
                path_str = click.prompt("Enter path for new key file", type=click.Path(writable=True))
                key, success = self.generate_and_save_key(path_str)
                if not success:
                    return None
                click.echo(f"Key generated and saved to {path_str}.")
                return key
            
            # Fallback interactive password entry
            password = click.prompt("Enter encryption key (base64 encoded)", hide_input=True, confirmation_prompt=True)
            # In production, you'd validate the base64 format or hash it. 
            # For this module, we return the raw bytes if valid, or try to encode it.
            try:
                # Simple check: if it's meant to be the raw key bytes, we return it as bytes
                # Assuming user provides a valid 32-byte key representation or base64
                return base64.b64decode(password)
            except Exception:
                click.echo("Invalid key format (expected base64).", err=True)
                return None
                
        except Exception as e:
            logger.error(f"Key prompt error: {e}")
            return None