from __future__ import annotations

import psutil
import toml
import secrets
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken

class PortAnalyzer:
    """
    A module for analyzing and recording local listening ports for development snapshots.
    
    This class utilizes psutil to gather process information, toml for serialization,
    and cryptography for securing sensitive snapshot data.
    """

    def __init__(self, encryption_key: Optional[bytes] = None) -> None:
        """
        Initialize the PortAnalyzer instance.
        
        Args:
            encryption_key: A Fernet encryption key. If None, encryption is disabled 
                            and snapshots are stored as plain text TOML.
        """
        self._encryption_key = encryption_key
        self._cipher = Fernet(encryption_key) if encryption_key else None

    def analyze(self) -> List[Dict[str, Any]]:
        """
        Analyzes the current system network connections and returns a list of listening ports.
        
        Returns:
            A list of dictionaries containing port, PID, protocol, and process details.
            Each dictionary includes 'port', 'pid', 'process_name', 'protocol', and 'timestamp'.
        """
        listening_ports = []
        current_time = datetime.now().isoformat()

        try:
            connections = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            raise PermissionError("Access denied while attempting to retrieve network connections.")
        except psutil.Error as e:
            raise RuntimeError(f"Failed to retrieve network connections: {e}")

        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                try:
                    process_info = {
                        'port': conn.laddr.port,
                        'address': str(conn.laddr),
                        'pid': conn.pid,
                        'protocol': 'tcp' if conn.family == 2 else 'udp',
                        'process_name': self._get_process_name(conn.pid),
                        'snapshot_timestamp': current_time
                    }
                    listening_ports.append(process_info)
                except psutil.NoSuchProcess:
                    # Process exited while we were iterating, skip it
                    continue
                except psutil.AccessDenied:
                    # Permission to access process details, record what we have
                    listening_ports.append({
                        'port': conn.laddr.port,
                        'address': str(conn.laddr),
                        'pid': conn.pid,
                        'protocol': 'tcp' if conn.family == 2 else 'udp',
                        'process_name': 'Unknown',
                        'snapshot_timestamp': current_time
                    })
                except Exception:
                    continue

        return listening_ports

    def _get_process_name(self, pid: int) -> str:
        """
        Retrieves the process name for a given PID.
        
        Args:
            pid: The Process ID to look up.
            
        Returns:
            The process name, or 'Unknown' if not accessible.
        """
        try:
            process = psutil.Process(pid)
            return process.name()
        except psutil.NoSuchProcess:
            return 'Unknown'
        except psutil.AccessDenied:
            return 'Unknown'
        except Exception:
            return 'Unknown'

    def _encrypt_data(self, data: Dict[str, Any]) -> bytes:
        """
        Encrypts snapshot data using Fernet encryption.
        
        Args:
            data: The dictionary data to encrypt.
            
        Returns:
            Encrypted bytes.
            
        Raises:
            ValueError: If no encryption key is configured.
        """
        if not self._cipher:
            raise ValueError("Encryption key is not configured.")
        return self._cipher.encrypt(toml.dumps(data).encode('utf-8'))

    def _decrypt_data(self, encrypted_data: bytes) -> Dict[str, Any]:
        """
        Decrypts snapshot data from bytes.
        
        Args:
            encrypted_data: The encrypted bytes to decrypt.
            
        Returns:
            The original dictionary data.
            
        Raises:
            ValueError: If decryption fails due to invalid token or format.
        """
        try:
            decrypted_bytes = self._cipher.decrypt(encrypted_data)
            return toml.loads(decrypted_bytes.decode('utf-8'))
        except InvalidToken:
            raise ValueError("Invalid decryption token or corrupted data.")

    def save_snapshot(self, path: Path, listening_ports: List[Dict[str, Any]]) -> None:
        """
        Saves the analysis snapshot to a file at the specified path.
        
        Args:
            path: The file path where the snapshot should be saved.
            listening_ports: The list of port data captured by analyze().
            
        Raises:
            IOError: If the file cannot be written.
            ValueError: If encryption is enabled but no key is provided.
        """
        try:
            meta = {
                'timestamp': datetime.now().isoformat(),
                'host': 'localhost',
                'version': '1.0.0'
            }
            full_snapshot = {
                'meta': meta,
                'data': listening_ports
            }

            path.parent.mkdir(parents=True, exist_ok=True)
            
            if self._cipher:
                content = self._encrypt_data(full_snapshot)
                path.write_bytes(content)
            else:
                with path.open('w', encoding='utf-8') as f:
                    toml.dump(full_snapshot, f)
        except PermissionError:
            raise PermissionError(f"Permission denied to write to {path}")
        except Exception as e:
            raise IOError(f"Failed to write snapshot to {path}: {e}")

    def load_snapshot(self, path: Path) -> Dict[str, Any]:
        """
        Loads a snapshot from the specified path.
        
        Args:
            path: The file path to load the snapshot from.
            
        Returns:
            The loaded dictionary data.
            
        Raises:
            IOError: If the file cannot be read.
            ValueError: If decryption fails or file format is invalid.
        """
        try:
            content = path.read_bytes()
            
            if self._cipher:
                try:
                    decrypted_content = self._decrypt_data(content)
                    return decrypted_content
                except ValueError:
                    # Fallback for unencrypted files if key is set, just in case
                    pass
            
            # Assume plain toml
            with path.open('r', encoding='utf-8') as f:
                return toml.load(f)
                
        except FileNotFoundError:
            raise FileNotFoundError(f"Snapshot file not found at {path}")
        except ValueError as e:
            raise ValueError(f"Failed to load or decrypt snapshot: {e}")
        except Exception as e:
            raise IOError(f"Error reading snapshot: {e}")

    def generate_key(self) -> bytes:
        """
        Generates a new Fernet encryption key.
        
        Returns:
            A random Fernet key (bytes).
        """
        return Fernet.generate_key()

    def set_encryption_key(self, key: bytes) -> None:
        """
        Sets a custom encryption key for the session.
        
        Args:
            key: The key bytes to use.
        """
        self._cipher = Fernet(key)
        self._encryption_key = key