import os
import sys
import toml
from typing import Dict, Any, List, Optional
from cryptography.fernet import Fernet
import psutil
import click

class SnapshotDecryptor:
    """
    Manages encryption and decryption of snapshot data using Fernet symmetric encryption.
    """

    def __init__(self, key: Optional[bytes] = None):
        """
        Initializes the SnapshotDecryptor with an encryption key.

        Args:
            key: Optional encryption key. If None, attempts to load from ENV 'DEV_SNAPSHOT_KEY'.
        """
        if key is not None:
            self.key = key
        else:
            env_key = os.environ.get('DEV_SNAPSHOT_KEY')
            if env_key:
                self.key = env_key.encode('utf-8')
            else:
                self.key = Fernet.generate_key()

        self.fernet = Fernet(self.key)

    def encrypt_data(self, data: str) -> str:
        """
        Encrypts a string using Fernet.

        Args:
            data: The plaintext string to encrypt.

        Returns:
            The encrypted ciphertext as a string.

        Raises:
            ValueError: If encryption fails.
        """
        try:
            encrypted = self.fernet.encrypt(data.encode('utf-8'))
            return encrypted.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt_data(self, encrypted_data: str) -> str:
        """
        Decrypts a string using Fernet.

        Args:
            encrypted_data: The ciphertext to decrypt.

        Returns:
            The decrypted plaintext string.

        Raises:
            ValueError: If decryption fails.
        """
        try:
            decoded = self.fernet.decrypt(encrypted_data.encode('utf-8'))
            return decoded.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")


class SnapshotRestorer:
    """
    Handles the restoration of a development environment from a snapshot state.
    """

    def __init__(self, restorer_id: str):
        """
        Initializes the SnapshotRestorer.

        Args:
            restorer_id: Identifier for the restoration session.
        """
        self.restorer_id = restorer_id
        self.encryption_manager = None

    def set_encryption_key(self, key: bytes):
        """
        Sets the encryption manager for decrypting the snapshot.

        Args:
            key: The Fernet encryption key.
        """
        self.encryption_manager = SnapshotDecryptor(key)

    def load_snapshot(self, snapshot_path: str) -> Dict[str, Any]:
        """
        Loads and decrypts a snapshot TOML file.

        Args:
            snapshot_path: Absolute path to the snapshot file.

        Returns:
            Dictionary containing the decrypted snapshot data.

        Raises:
            FileNotFoundError: If the snapshot file does not exist.
            IOError: If reading the file fails.
        """
        try:
            with open(snapshot_path, 'r', encoding='utf-8') as f:
                encrypted_content = f.read()

            if self.encryption_manager:
                try:
                    decrypted_str = self.encryption_manager.decrypt_data(encrypted_content)
                    return toml.loads(decrypted_str)
                except ValueError as e:
                    raise IOError(f"Decryption failed for snapshot: {str(e)}")
            else:
                return toml.loads(encrypted_content)

        except FileNotFoundError:
            raise FileNotFoundError(f"Snapshot file not found: {snapshot_path}")
        except Exception as e:
            raise IOError(f"Failed to load snapshot: {str(e)}")

    def restore_environment_variables(self, snapshot_data: Dict[str, Any]) -> Dict[str, int]:
        """
        Restores environment variables defined in the snapshot.

        Args:
            snapshot_data: The snapshot dictionary.

        Returns:
            Dictionary mapping variable names to restore success status (1 for success, 0 for fail).
        """
        results = {}
        env_vars = snapshot_data.get('environment', [])
        for var_name, value in env_vars.items():
            try:
                if isinstance(value, str):
                    os.environ[var_name] = value
                    results[var_name] = 1
                else:
                    os.environ[var_name] = str(value)
                    results[var_name] = 1
            except (PermissionError, OSError, KeyError) as e:
                results[var_name] = 0
                sys.stderr.write(f"Warning: Failed to set env var {var_name}: {str(e)}\n")
        return results

    def verify_system_state(self) -> Dict[str, List[str]]:
        """
        Checks the current running processes to verify environment state.

        Returns:
            Dictionary containing list of running process names for verification.
        """
        try:
            running_processes = [p.name() for p in psutil.process_iter(['name'])]
            return {"running_processes": running_processes}
        except psutil.NoSuchProcess:
            return {"running_processes": [], "status": "errors_detected"}
        except Exception as e:
            sys.stderr.write(f"Error during system state verification: {str(e)}\n")
            return {"running_processes": [], "status": "error"}

    def apply_system_configs(self, snapshot_data: Dict[str, Any]) -> int:
        """
        Applies system-level configurations or scripts defined in the snapshot.
        This is a placeholder for specific restore logic like restarting services.

        Args:
            snapshot_data: The snapshot dictionary.

        Returns:
            Number of configurations successfully applied.
        """
        configs = snapshot_data.get('configs', [])
        count = 0
        for config_item in configs:
            try:
                # Logic to apply configs (e.g., reload services, modify system settings)
                # This is a generic placeholder for restoration logic
                if config_item.get('type') == 'process':
                    # In a real scenario, this might use subprocess or systemd interaction
                    # Here we just simulate success for the logic flow
                    pass
                count += 1
            except Exception as e:
                sys.stderr.write(f"Warning: Failed config application: {config_item.get('name')} -> {str(e)}")
        return count

    def restore_snapshot(self, snapshot_path: str, encryption_key: Optional[bytes] = None) -> bool:
        """
        Orchestrates the full restoration process from a snapshot file.

        Args:
            snapshot_path: Path to the snapshot file.
            encryption_key: Optional encryption key bytes.

        Returns:
            True if restoration completed without critical failure, False otherwise.
        """
        success = False
        try:
            if encryption_key:
                self.set_encryption_key(encryption_key)

            snapshot_data = self.load_snapshot(snapshot_path)

            if 'environment' not in snapshot_data:
                sys.stderr.write("Error: Invalid snapshot format, missing 'environment'.\n")
                return False

            env_results = self.restore_environment_variables(snapshot_data)
            success = all(v == 1 for v in env_results.values())

            if success:
                self.apply_system_configs(snapshot_data)
                status_report = self.verify_system_state()
                # Log success silently or via click in CLI context
                return True
            else:
                sys.stderr.write("Restoration completed with some environment variable failures.\n")
                return False

        except FileNotFoundError as e:
            sys.stderr.write(f"Fatal: Snapshot not found: {str(e)}\n")
            return False
        except Exception as e:
            sys.stderr.write(f"Fatal: Restoration failed: {str(e)}\n")
            return False


@click.group()
def restore_cli():
    """Restore utility CLI group for Dev Snapshot project."""
    pass


@restore_cli.command('restore')
@click.argument('snapshot_path', type=click.Path(exists=True))
@click.option('--key', '-k', envvar='DEV_SNAPSHOT_KEY', help='Encryption key for snapshot.')
@click.pass_context
def restore_command(ctx, snapshot_path, key):
    """
    Restores the development environment state from a snapshot file.

    Args:
        snapshot_path: Path to the snapshot .toml file.
        key: Encryption key for decryption.
    """
    try:
        restorer = SnapshotRestorer("cli_session_01")
        key_bytes = key.encode('utf-8') if key else None
        success = restorer.restore_snapshot(snapshot_path, key_bytes)
        if not success:
            sys.exit(1)
        ctx.invoke(verify_status)
    except Exception as e:
        sys.stderr.write(f"CLI Error: {str(e)}\n")
        sys.exit(1)


@restore_cli.command('verify')
@click.pass_context
def verify_status(ctx):
    """
    Verifies the current system state against psutil data.
    """
    restorer = SnapshotRestorer("verify_session_01")
    try:
        state = restorer.verify_system_state()
        click.echo(f"Verified {len(state.get('running_processes', []))} processes running.")
    except Exception as e:
        sys.stderr.write(f"Verification failed: {str(e)}\n")
        sys.exit(1)


# Exposed members for programmatic use
__all__ = ['SnapshotDecryptor', 'SnapshotRestorer', 'restore_command', 'verify_status', 'restore_cli']
__author__ = 'DevOps Team'