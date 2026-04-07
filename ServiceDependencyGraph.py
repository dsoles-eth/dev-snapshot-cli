import os
import platform
import datetime
import base64
import psutil
import toml
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidToken

@dataclass
class DependencyNode:
    """Represents a single service dependency in the graph."""
    name: str
    service_type: str
    port: Optional[int]
    pid: Optional[int]
    status: str
    timestamp: str

    @staticmethod
    def from_process_info(proc: psutil.Process, active_ports: Optional[List[int]] = None) -> "DependencyNode":
        """
        Create a DependencyNode from a psutil Process object.
        
        Args:
            proc: A psutil Process instance.
            active_ports: Optional list of active ports associated with this process.
            
        Returns:
            DependencyNode: An instance representing the process.
        """
        try:
            name = proc.name() or "unknown"
            service_type = "application"
            port = active_ports[0] if active_ports else None
            
            if "postgres" in name.lower():
                service_type = "database"
                port = port or 5432
            elif "mysql" in name.lower() or "mariadb" in name.lower():
                service_type = "database"
                port = port or 3306
            elif "redis" in name.lower():
                service_type = "cache"
                port = port or 6379
            elif "mongo" in name.lower():
                service_type = "database"
                port = port or 27017
            elif "nginx" in name.lower():
                service_type = "webserver"
                port = port or 80
            elif "node" in name.lower() or "python" in name.lower():
                service_type = "application"
                port = port or 8080
            elif "docker" in name.lower():
                service_type = "container_host"
                port = None
            
            if port is None and active_ports:
                port = max(active_ports)

            return DependencyNode(
                name=proc.name(),
                service_type=service_type,
                port=port,
                pid=proc.pid,
                status=proc.status(),
                timestamp=datetime.datetime.now().isoformat()
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return DependencyNode(
                name="Unknown",
                service_type="unknown",
                port=None,
                pid=proc.pid,
                status="unavailable",
                timestamp=datetime.datetime.now().isoformat()
            )

class ServiceDependencyGraph:
    """
    A class to map active local dependencies and manage environment snapshots.
    
    This class utilizes psutil for system scanning, toml for serialization,
    and cryptography for secure snapshot storage.
    """

    KEY_ENV_VAR = "DEV_SNAPSHOT_ENCRYPTION_KEY"
    METADATA = {
        "version": "1.0.0"
    }

    def __init__(self):
        self._nodes: List[DependencyNode] = []
        self._key: Optional[Fernet] = None

    def _get_hostname(self) -> str:
        """Retrieves the system hostname safely."""
        try:
            return os.uname().nodename
        except AttributeError:
            return platform.node()

    def _get_encryption_key(self) -> bytes:
        """
        Retrieves the encryption key from the environment or generates a new one.
        
        Returns:
            bytes: A valid Fernet key.
        """
        key_str = os.getenv(self.KEY_ENV_VAR)
        if key_str:
            return base64.urlsafe_b64decode(key_str)
        return Fernet.generate_key()

    def _set_key(self, key: bytes) -> None:
        """
        Initializes the Fernet instance with the provided key.
        
        Args:
            key: The raw encryption key bytes.
        """
        self._key = Fernet(key)

    def scan_dependencies(self) -> List[DependencyNode]:
        """
        Scans the local system for active dependencies using psutil.
        
        Returns:
            List[DependencyNode]: A list of detected dependency nodes.
        """
        self._nodes = []
        connections = []
        conn_map: Dict[int, List[int]] = {}
        
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.laddr.pid:
                    if conn.laddr.pid not in conn_map:
                        conn_map[conn.laddr.pid] = []
                    conn_map[conn.laddr.pid].append(conn.laddr.port)

            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    ports = conn_map.get(proc.pid)
                    node = DependencyNode.from_process_info(proc, ports)
                    if node.status != "unavailable" or node.pid:
                        self._nodes.append(node)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except psutil.Error as e:
            raise RuntimeError(f"Failed to scan processes: {e}")
        
        return self._nodes

    def get_dependencies(self) -> List[DependencyNode]:
        """
        Returns the current list of discovered dependencies.
        
        Returns:
            List[DependencyNode]: The list of dependency nodes.
        """
        return self._nodes

    def create_snapshot(self) -> str:
        """
        Creates an encrypted snapshot of the current dependency graph.
        
        Returns:
            str: Base64 encoded encrypted snapshot string.
        """
        try:
            self._set_key(self._get_encryption_key())
            if not self._key:
                raise ValueError("Encryption key not initialized")

            nodes_data = [
                {
                    "name": n.name,
                    "service_type": n.service_type,
                    "port": n.port,
                    "pid": n.pid,
                    "status": n.status,
                    "timestamp": n.timestamp
                }
                for n in self._nodes
            ]

            metadata = {
                "created_at": datetime.datetime.now().isoformat(),
                "hostname": self._get_hostname(),
                "version": self.METADATA["version"]
            }

            snapshot_data = {
                "metadata": metadata,
                "dependencies": nodes_data
            }

            toml_str = toml.dumps(snapshot_data)
            encrypted_bytes = self._key.encrypt(toml_str.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')

        except (psutil.Error, OSError, ValueError) as e:
            raise RuntimeError(f"Failed to create snapshot: {e}")

    def restore_snapshot(self, snapshot_data: str) -> bool:
        """
        Restores a graph from an encrypted snapshot string.
        
        Args:
            snapshot_data: The base64 encoded encrypted snapshot string.
            
        Returns:
            bool: True if restoration was successful, False otherwise.
        """
        try:
            self._set_key(self._get_encryption_key())
            if not self._key:
                raise ValueError("Encryption key not initialized")

            encrypted_bytes = base64.urlsafe_b64decode(snapshot_data.encode('utf-8'))
            decrypted_bytes = self._key.decrypt(encrypted_bytes)
            decrypted_str = decrypted_bytes.decode('utf-8')

            restored_data = toml.loads(decrypted_str)

            self._nodes = []
            dependencies = restored_data.get("dependencies", [])
            for d in dependencies:
                node = DependencyNode(
                    name=d.get("name", "Unknown"),
                    service_type=d.get("service_type", "unknown"),
                    port=d.get("port"),
                    pid=d.get("pid"),
                    status=d.get("status", "unknown"),
                    timestamp=d.get("timestamp", datetime.datetime.now().isoformat())
                )
                self._nodes.append(node)

            return True

        except (InvalidToken, KeyError, toml.TomlDecodeError) as e:
            print(f"Failed to restore snapshot: {e}")
            return False