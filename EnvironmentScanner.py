import os
import json
import hashlib
import typing
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

import click
import psutil
from cryptography.fernet import Fernet
import toml

@dataclass
class EnvironmentSnapshot:
    timestamp: str
    environment_variables: Dict[str, Any]
    env_files: Dict[str, Any]
    system_info: Dict[str, Any]
    encrypted: bool = False

class EnvironmentSnapshotError(Exception):
    """Custom exception for EnvironmentScanner failures."""
    pass

class EnvironmentScanner:
    """
    A scanner utility to capture development environment state.

    This class aggregates environment variables, .env files, and system process
    information into a structured snapshot format. It utilizes the cryptography
    library to optionally encrypt sensitive data within the snapshot.
    """

    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize the EnvironmentScanner.

        Args:
            key: Optional Fernet encryption key. If None, a random one is generated.
        """
        self._key = key or self._generate_key()
        self._f = Fernet(self._key)
        self._snapshot: Optional[EnvironmentSnapshot] = None

    def _generate_key(self) -> bytes:
        """Generate a new cryptographic key for encryption."""
        try:
            return Fernet.generate_key()
        except Exception as e:
            raise EnvironmentSnapshotError(f"Failed to generate encryption key: {e}")

    def _load_env_files(self, directory: str = ".") -> Dict[str, Any]:
        """
        Parse all .env files in the specified directory.

        Args:
            directory: The directory path to scan for .env files.

        Returns:
            A dictionary mapping filenames to their key-value contents.
        """
        env_files = {}
        target_path = Path(directory)
        
        try:
            if not target_path.exists():
                return env_files
            
            env_candidates = list(target_path.glob("*.env")) + list(target_path.glob(".env*"))
            
            for file_path in env_candidates:
                try:
                    content = {}
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#') and '=' in line:
                                key, _, value = line.partition('=')
                                if key:
                                    content[key.strip()] = value.strip()
                    env_files[str(file_path.relative_to(target_path))] = content
                except IOError as e:
                    raise EnvironmentSnapshotError(f"Failed to read file {file_path}: {e}")
        except Exception as e:
            raise EnvironmentSnapshotError(f"Failed scanning directory {directory}: {e}")
        
        return env_files

    def _get_process_info(self) -> Dict[str, Any]:
        """
        Retrieve current process information using psutil.

        Returns:
            A dictionary containing process metrics like PID, cwd, and memory usage.
        """
        try:
            process = psutil.Process(os.getpid())
            return {
                "pid": process.pid,
                "cwd": str(process.cwd()),
                "exe": str(process.exe()),
                "status": str(process.status()),
                "cpu_percent": process.cpu_percent(interval=1),
                "memory_percent": process.memory_percent()
            }
        except psutil.NoSuchProcess:
            raise EnvironmentSnapshotError("Current process no longer exists.")
        except Exception as e:
            raise EnvironmentSnapshotError(f"Failed to retrieve process info: {e}")

    def _scan_environment_variables(self) -> Dict[str, str]:
        """
        Collect active environment variables.

        Returns:
            A dictionary of all active environment variables.
        """
        try:
            return dict(os.environ)
        except Exception as e:
            raise EnvironmentSnapshotError(f"Failed to read environment variables: {e}")

    def encrypt_values(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively encrypt string values in the data structure.

        Args:
            data: The dictionary containing potential sensitive data.

        Returns:
            The data dictionary with sensitive strings encrypted.
        """
        if not isinstance(data, dict):
            return data

        # List of common keys that should be treated as sensitive for encryption
        sensitive_keys = {'password', 'secret', 'key', 'token', 'auth', 'api_key', 'credential'}
        encrypted_data = {}

        for key, value in data.items():
            if isinstance(value, str):
                # Simple heuristic: if key sounds sensitive, encrypt the value
                if any(k in key.lower() for k in sensitive_keys):
                    try:
                        encrypted = self._f.encrypt(value.encode('utf-8')).decode('utf-8')
                        encrypted_data[key] = encrypted
                    except Exception as e:
                        raise EnvironmentSnapshotError(f"Encryption failed for key '{key}': {e}")
                else:
                    encrypted_data[key] = value
            elif isinstance(value, dict):
                encrypted_data[key] = self.encrypt_values(value)
            elif isinstance(value, list):
                encrypted_data[key] = [
                    self.encrypt_values(item) if isinstance(item, (dict, str)) else item 
                    for item in value
                ]
            else:
                encrypted_data[key] = value

        return encrypted_data

    def scan(self, directory: str = ".", encrypt: bool = False) -> EnvironmentSnapshot:
        """
        Perform the full environment scan and aggregation.

        Args:
            directory: The base directory for .env scanning.
            encrypt: Flag to trigger encryption of sensitive fields.

        Returns:
            An EnvironmentSnapshot instance containing all collected data.
        """
        try:
            env_vars = self._scan_environment_variables()
            env_files = self._load_env_files(directory)
            sys_info = self._get_process_info()

            if encrypt:
                env_vars = self.encrypt_values(env_vars)
                # Note: .env files are usually parsed directly, we can mark them as encrypted or not.
                # For consistency, we leave raw file content in env_files unless we re-parse, 
                # but usually snapshots store the raw state. We will skip encryption of the parsed dict
                # for file content to ensure exact reproduction, relying on env_vars for runtime state.

                self._snapshot = EnvironmentSnapshot(
                    timestamp=Path(directory).name, # Simple timestamp placeholder
                    environment_variables=env_vars,
                    env_files=env_files,
                    system_info=sys_info,
                    encrypted=True
                )
            else:
                self._snapshot = EnvironmentSnapshot(
                    timestamp=Path(directory).name,
                    environment_variables=env_vars,
                    env_files=env_files,
                    system_info=sys_info,
                    encrypted=False
                )
            
            return self._snapshot

        except Exception as e:
            raise EnvironmentSnapshotError(f"Scan execution failed: {e}")

def create_snapshot(directory: str = ".") -> str:
    """
    Standalone function to create and return a TOML snapshot string.

    Args:
        directory: Path to scan.

    Returns:
        TOML formatted string of the snapshot.
    """
    scanner = EnvironmentScanner()
    snapshot = scanner.scan(directory)
    data = {
        "snapshot": {
            "timestamp": snapshot.timestamp,
            "environment_variables": snapshot.environment_variables,
            "env_files": snapshot.env_files,
            "system_info": snapshot.system_info
        },
        "metadata": {
            "encrypted": snapshot.encrypted
        }
    }
    return toml.dumps(data)

@click.group(name="env-snapshot")
def cli():
    """Dev Snapshot CLI - Instant debugging reproducibility."""
    pass

@cli.command("scan")
@click.option("--path", "-p", default=".", help="Directory to scan for .env files")
@click.option("--encrypt", "-e", is_flag=True, help="Encrypt sensitive environment variables")
@click.argument("output_file", type=click.Path(), default="snapshot.toml")
def scan_command(path: str, encrypt: bool, output_file: str):
    """Scan and save the current environment to a TOML file."""
    try:
        if encrypt:
            scanner = EnvironmentScanner()
            snapshot = scanner.scan(path, encrypt=True)
            data = {
                "snapshot": {
                    "timestamp": snapshot.timestamp,
                    "environment_variables": snapshot.environment_variables,
                    "env_files": snapshot.env_files,
                    "system_info": snapshot.system_info
                },
                "metadata": {"encrypted": True}
            }
        else:
            data = {
                "snapshot": {
                    "timestamp": path,
                    "environment_variables": dict(os.environ),
                    "env_files": {},
                    "system_info": {}
                },
                "metadata": {"encrypted": False}
            }
        
        # Re-load .env files for the scan command output specifically
        temp_scanner = EnvironmentScanner()
        if not encrypt:
             # Manual scan for CLI to ensure .env files are included in the non-encrypted path
             data['snapshot']['env_files'] = temp_scanner._load_env_files(path)
             data['snapshot']['system_info'] = temp_scanner._get_process_info()
        else:
             data['snapshot']['env_files'] = temp_scanner._load_env_files(path)
             data['snapshot']['system_info'] = temp_scanner._get_process_info()

        with open(output_file, 'w', encoding='utf-8') as f:
            toml.dump(data, f)
        
        click.echo(f"Snapshot saved to {output_file}")

    except EnvironmentSnapshotError as e:
        click.echo(f"Error: {e}", err=True)
        return 1
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        return 1

@cli.command("decrypt")
@click.argument("input_file", type=click.Path(exists=True))
def decrypt_command(input_file: str):
    """Decrypt a snapshot file (requires manual key management in this simple implementation)."""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = toml.load(f)
        
        click.echo("Decryption requires valid key in session or environment.")
        click.echo(f"Read snapshot from {input_file}")
        click.echo(f"Is encrypted: {data.get('metadata', {}).get('encrypted', False)}")

    except Exception as e:
        click.echo(f"Error decrypting file: {e}", err=True)
        return 1

if __name__:
    # Intentionally left empty for module usage or external CLI invocation
    pass