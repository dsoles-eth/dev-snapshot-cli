import pytest
import os
import datetime
from unittest.mock import patch, MagicMock, mock_open
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidToken
import psutil

from ServiceDependencyGraph import ServiceDependencyGraph, DependencyNode


@pytest.fixture
def mock_env_key():
    """Fixture for environment encryption key"""
    with patch.dict(os.environ, {ServiceDependencyGraph.KEY_ENV_VAR: "mock_key_value"}):
        yield "mock_key_value"


@pytest.fixture
def service_dependency_graph():
    """Fixture for ServiceDependencyGraph instance"""
    with patch.object(ServiceDependencyGraph, '_get_encryption_key', return_value=Fernet.generate_key()):
        yield ServiceDependencyGraph()


@pytest.fixture
def mock_process_info():
    """Fixture for mock process information"""
    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.name.return_value = "postgres"
    mock_proc.pid = 1234
    mock_proc.status.return_value = "running"
    return mock_proc


@pytest.fixture
def mock_dependency_node(mock_process_info):
    """Fixture for mock DependencyNode"""
    return DependencyNode(
        name="postgres",
        service_type="database",
        port=5432,
        pid=1234,
        status="running",
        timestamp=datetime.datetime.now().isoformat()
    )


class TestDependencyNode:
    """Test cases for DependencyNode class"""

    @patch('ServiceDependencyGraph.psutil.Process')
    def test_from_process_info_application(self, mock_proc_class):
        """Test DependencyNode creation for application process"""
        mock_proc = MagicMock()
        mock_proc.name.return_value = "python"
        mock_proc.pid = 5678
        mock_proc.status.return_value = "running"
        mock_proc_class.return_value = mock_proc

        node = DependencyNode.from_process_info(mock_proc, [8080])

        assert node.name == "python"
        assert node.service_type == "application"
        assert node.port == 8080
        assert node.pid == 5678
        assert node.status == "running"
        assert node.timestamp is not None

    @patch('ServiceDependencyGraph.psutil.Process')
    def test_from_process_info_database_postgres(self, mock_proc_class):
        """Test DependencyNode creation for postgres database"""
        mock_proc = MagicMock()
        mock_proc.name.return_value = "postgres"
        mock_proc.pid = 9999
        mock_proc.status.return_value = "running"
        mock_proc_class.return_value = mock_proc

        node = DependencyNode.from_process_info(mock_proc)

        assert node.service_type == "database"
        assert node.port == 5432
        assert node.pid == 9999

    @patch('ServiceDependencyGraph.psutil.Process')
    def test_from_process_info_unavailable(self, mock_proc_class):
        """Test DependencyNode creation when process is unavailable"""
        mock_proc = MagicMock()
        mock_proc.pid = 1111
        type(mock_proc).name = MagicMock(side_effect=psutil.NoSuchProcess)
        mock_proc_class.return_value = mock_proc

        node = DependencyNode.from_process_info(mock_proc)

        assert node.name == "Unknown"
        assert node.service_type == "unknown"
        assert node.status == "unavailable"
        assert node.pid == 1111


class TestServiceDependencyGraphMethods:
    """Test cases for ServiceDependencyGraph methods"""

    @patch('ServiceDependencyGraph.os.uname')
    def test_get_hostname_uname(self, mock_uname, service_dependency_graph):
        """Test hostname retrieval via os.uname"""
        mock_uname.return_value.nodename = "test-host"
        hostname = service_dependency_graph._get_hostname()
        assert hostname == "test-host"

    @patch('ServiceDependencyGraph.platform.node')
    @patch('ServiceDependencyGraph.os.uname', side_effect=AttributeError)
    def test_get_hostname_fallback(self, mock_uname, mock_platform, service_dependency_graph):
        """Test hostname retrieval fallback to platform.node"""
        mock_platform.return_value = "fallback-host"
        hostname = service_dependency_graph._get_hostname()
        assert hostname == "fallback-host"

    @patch('ServiceDependencyGraph.os.getenv')
    @patch('ServiceDependencyGraph.base64.urlsafe_b64decode')
    def test_get_encryption_key_from_env(self, mock_decode, mock_getenv, service_dependency_graph):
        """Test encryption key retrieval from environment"""
        mock_getenv.return_value = "mock_encoded_key"
        mock_decode.return_value = b"mock_key"
        key = service_dependency_graph._get_encryption_key()
        assert key == b"mock_key"

    @patch('ServiceDependencyGraph.os.getenv', return_value=None)
    @patch('ServiceDependencyGraph.Fernet.generate_key')
    def test_get_encryption_key_generated(self, mock_generate, mock_getenv, service_dependency_graph):
        """Test encryption key generation when not in environment"""
        mock_generate.return_value = b"newly_generated_key"
        key = service_dependency_graph._get_encryption_key()
        assert key == b"newly_generated_key"

    def test_set_key_initializes_fernet(self, service_dependency_graph):
        """Test key initialization creates Fernet instance"""
        key = Fernet.generate_key()
        service_dependency_graph._set_key(key)
        assert service_dependency_graph._key is not None
        assert isinstance(service_dependency_graph._key, Fernet)


class TestScanDependencies:
    """Test cases for scan_dependencies method"""

    @patch('ServiceDependencyGraph.psutil.net_connections')
    @patch('ServiceDependencyGraph.psutil.process_iter')
    def test_scan_dependencies_happy_path(self, mock_process_iter, mock_net_conn, service_dependency_graph):
        """Test successful dependency scan"""
        mock_connections = [
            MagicMock(laddr=MagicMock(pid=1234, port=5432))
        ]
        mock_process = MagicMock(name="postgres", pid=1234)
        mock_process.name.return_value = "postgres"
        mock_process.pid = 1234
        mock_process.status.return_value = "running"

        mock_net_conn.return_value = mock_connections
        mock_process_iter.return_value = iter([mock_process])

        nodes = service_dependency_graph.scan_dependencies()
        assert len(nodes) > 0
        assert any(node.service_type == "database" for node in nodes)

    @patch('ServiceDependencyGraph.psutil.net_connections')
    @patch('ServiceDependencyGraph.psutil.process_iter')
    def test_scan_dependencies_no_connections(self, mock_process_iter, mock_net_conn, service_dependency_graph):
        """Test scan when no active connections"""
        mock_net_conn.return_value = []
        mock_process = MagicMock(name="test", pid=9999)
        mock_process.name.return_value = "test"
        mock_process.pid = 9999
        mock_process.status.return_value = "running"
        mock_process_iter.return_value = iter([mock_process])

        nodes = service_dependency_graph.scan_dependencies()
        assert len(nodes) > 0

    @patch('ServiceDependencyGraph.psutil.net_connections')
    @patch('ServiceDependencyGraph.psutil.process_iter')
    def test_scan_dependencies_access_denied(self, mock_process_iter, mock_net_conn, service_dependency_graph):
        """Test scan when access denied to some processes"""
        mock_net_conn.return_value = []
        
        def process_generator():
            mock_proc = MagicMock(name="restricted", pid=8888)
            mock_proc.name.return_value = "restricted"
            mock_proc.pid = 8888
            mock_proc.status.return_value = "running"
            mock_proc.__iter__ = MagicMock(side_effect=psutil.AccessDenied)
            yield mock_proc
        
        mock_process_iter.return_value = process_generator()

        nodes = service_dependency_graph.scan_dependencies()
        assert service_dependency_graph.get_dependencies() == []


class TestGetDependencies:
    """Test cases for get_dependencies method"""

    def test_get_dependencies_empty(self, service_dependency_graph):
        """Test get_dependencies when no nodes"""
        nodes = service_dependency_graph.get_dependencies()
        assert nodes == []

    @patch.object(ServiceDependencyGraph, '_get_encryption_key', return_value=Fernet.generate_key())
    def test_get_dependencies_with_nodes(self, mock_key, service_dependency_graph):
        """Test get_dependencies returns actual nodes"""
        mock_node = DependencyNode(
            name="test_service",
            service_type="application",
            port=8000,
            pid=1234,
            status="running",
            timestamp=datetime.datetime.now().isoformat()
        )
        service_dependency_graph._nodes = [mock_node]
        nodes = service_dependency_graph.get_dependencies()
        assert len(nodes) == 1
        assert nodes[0].name == "test_service"

    def test_get_dependencies_returns_copy(self, service_dependency_graph):
        """Test that get_dependencies returns list reference that can be modified"""
        mock_node = DependencyNode(
            name="test",
            service_type="test",
            port=1234,
            pid=123,
            status="running",
            timestamp=datetime.datetime.now().isoformat()
        )
        service_dependency_graph._nodes = [mock_node]
        nodes = service_dependency_graph.get_dependencies()
        initial_len = len(nodes)
        service_dependency_graph._nodes.append(mock_node)
        assert len(nodes) == initial_len


class TestCreateSnapshot:
    """Test cases for create_snapshot method"""

    @patch.object(ServiceDependencyGraph, '_get_encryption_key')
    @patch('ServiceDependencyGraph.Fernet.encrypt')
    @patch('ServiceDependencyGraph.base64.urlsafe_b64encode')
    def test_create_snapshot_happy_path(self, mock_b64encode, mock_encrypt, mock_get_key, service_dependency_graph):
        """Test successful snapshot creation"""
        mock_get_key.return_value = Fernet.generate_key()
        service_dependency_graph._nodes = [
            DependencyNode(
                name="postgres",
                service_type="database",
                port=5432,
                pid=1234,
                status="running",
                timestamp=datetime.datetime.now().isoformat()
            )
        ]
        mock_b64encode.return_value = b"encoded_snapshot"
        
        snapshot = service_dependency_graph.create_snapshot()
        
        assert snapshot == "encoded_snapshot"
        assert isinstance(snapshot, str)

    @patch.object(ServiceDependencyGraph, '_get_encryption_key', return_value=Fernet.generate_key())
    def test_create_snapshot_without_nodes(self, mock_key, service_dependency_graph):
        """Test snapshot creation with empty node list"""
        snapshot = service_dependency_graph.create_snapshot()
        assert snapshot is not None

    @patch.object(ServiceDependencyGraph, '_get_encryption_key')
    @patch('ServiceDependencyGraph.Fernet.encrypt', side_effect=ValueError("Key error"))
    def test_create_snapshot_key_error(self, mock_encrypt, mock_get_key, service_dependency_graph):
        """Test snapshot creation with encryption failure"""
        mock_get_key.return_value = Fernet.generate_key()
        service_dependency_graph._nodes = [
            DependencyNode(
                name="postgres",
                service_type="database",
                port=5432,
                pid=1234,
                status="running",
                timestamp=datetime.datetime.now().isoformat()
            )
        ]
        
        with pytest.raises(RuntimeError, match="Failed to create snapshot"):
            service_dependency_graph.create_snapshot()


class TestRestoreSnapshot:
    """Test cases for restore_snapshot method"""

    @patch.object(ServiceDependencyGraph, '_get_encryption_key')
    @patch('ServiceDependencyGraph.Fernet.decrypt')
    @patch('ServiceDependencyGraph.toml.loads')
    @patch('ServiceDependencyGraph.base64.urlsafe_b64decode')
    def test_restore_snapshot_happy_path(self, mock_b64decode, mock_toml_loads, mock_decrypt, mock_get_key, service_dependency_graph):
        """Test successful snapshot restoration"""
        mock_get_key.return_value = Fernet.generate_key()
        mock_b64decode.return_value = b"encrypted_data"
        mock_decrypt.return_value = b'toml_content'
        mock_toml_loads.return_value = {
            "metadata": {"created_at": "2024-01-01"},
            "dependencies": [
                {"name": "postgres", "service_type": "database", "port": 5432, "pid": 1234, "status": "running"}
            ]
        }
        
        result = service_dependency_graph.restore_snapshot("encoded_snapshot")
        
        assert result is True
        assert len(service_dependency_graph._nodes) == 1
        assert service_dependency_graph._nodes[0].name == "postgres"

    @patch.object(ServiceDependencyGraph, '_get_encryption_key')
    @patch('ServiceDependencyGraph.base64.urlsafe_b64decode')
    def test_restore_snapshot_invalid_token(self, mock_b64decode, mock_get_key, service_dependency_graph):
        """Test restoration with invalid encryption token"""
        mock_get_key.return_value = Fernet.generate_key()
        mock_b64decode.return_value = b"invalid_data"
        
        result = service_dependency_graph.restore_snapshot("invalid_snapshot")
        
        assert result is False

    @patch.object(ServiceDependencyGraph, '_get_encryption_key')
    @patch('ServiceDependencyGraph.toml.loads')
    @patch('ServiceDependencyGraph.base64.urlsafe_b64decode')
    def test_restore_snapshot_corrupted_toml(self, mock_b64decode, mock_toml_loads, mock_get_key, service_dependency_graph):
        """Test restoration with corrupted TOML data"""
        mock_get_key.return_value = Fernet.generate_key()
        mock_b64decode.return_value = b"encrypted_data"
        mock_toml_loads.side_effect = toml.TomlDecodeError("Invalid TOML")
        
        result = service_dependency_graph.restore_snapshot("encoded_snapshot")
        
        assert result is False