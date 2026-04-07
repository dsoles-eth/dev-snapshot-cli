# Dev Snapshot CLI

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/dev-snapshot-cli.svg)](https://pypi.org/project/dev-snapshot-cli/)
[![Stars](https://img.shields.io/github/stars/username/dev-snapshot-cli?style=social)](https://github.com/username/dev-snapshot-cli)

**Dev Snapshot CLI** (`dev-snapshot-cli`) is a robust command-line interface utility designed to snapshot local development environments to ensure instant debugging reproducibility across teams. It captures critical state information—ranging from environment variables and active ports to git commit hashes—and securely stores them for later restoration.

Built for backend developers, DevOps engineers, and technical leads, this tool eliminates the "it works on my machine" problem by providing a tamper-proof, encrypted artifact of your development setup.

## Features

*   **Full Environment Capture**: Aggregates active environment variables and `.env` file contents for the current directory.
*   **Port & Process Mapping**: Identifies listening local ports and associates them with process IDs to replicate network states.
*   **Version Control State**: Captures current git branch, commit hash, and tracks dirty file changes for precise code replication.
*   **Service Dependency Graph**: Maps active local dependencies such as Docker containers or local database connections.
*   **Military-Grade Security**: Sensitive data is encrypted using `cryptography` before storage or sharing to prevent accidental leaks.
*   **One-Click Sharing**: Exports snapshots to shareable artifacts or generates unique reference IDs for easy team distribution.
*   **Instant Restoration**: Reconstructs the saved environment state on remote machines or different local setups with a single command.

## Installation

Install the latest version via PyPI:

```bash
pip install dev-snapshot-cli
```

Ensure your environment has Python 3.8 or higher. The package includes its dependencies (`click`, `psutil`, `cryptography`, `toml`) automatically.

## Quick Start

Follow this workflow to capture a snapshot, secure it, and restore it on another machine.

```bash
# 1. Capture current environment state (auto-detects .env, ports, git, etc.)
dev-snapshot snapshot --name "backend-debug-01"

# 2. The CLI will generate an encrypted payload and a shareable ID
# Output: Snapshot ID: 8f3a-2b9c-1d4e | Status: Securely Encrypted

# 3. Restore the environment on a new machine or VM
dev-snapshot restore --id "8f3a-2b9c-1d4e" --key "YOUR_SECRET_KEY"

# 4. Verify restoration
dev-snapshot status
```

## Usage

The CLI offers a set of subcommands to manage development snapshots.

### `snapshot`
Creates a new snapshot of the current working directory.

```bash
dev-snapshot snapshot [OPTIONS]
```
**Options:**
*   `--name <NAME>`: Optional custom name for the snapshot.
*   `--encrypt`: Force encryption of the payload (default: on for sensitive data).
*   `--exclude <FILE>`: Glob pattern to exclude files from the state capture.

### `share`
Generates a shareable link or artifact containing the snapshot reference.

```bash
dev-snapshot share [SNAPSHOT_ID] [OPTIONS]
```
**Options:**
*   `--output <FILE>`: Save the reference ID to a text file.
*   `--format <TYPE>`: Output format (default: `text`).

### `restore`
Rebuilds the environment based on a saved snapshot ID.

```bash
dev-snapshot restore --id <SNAPSHOT_ID> [OPTIONS]
```
**Options:**
*   `--key <KEY>`: The decryption key for the payload.
*   `--dry-run`: Preview what changes will be applied without executing them.
*   `--force`: Skip confirmation prompts.

### `status`
Displays detailed information about the current local environment state.

```bash
dev-snapshot status
```

## Architecture

The project is modular, utilizing the following core components:

| Module | Description |
| :--- | :--- |
| **EnvironmentScanner** | Aggregates all active environment variables and `.env` file contents for the current directory. |
| **PortAnalyzer** | Identifies and records all listening local ports and associated process IDs using `psutil`. |
| **GitStateFetcher** | Captures current branch, commit hash, and dirty file changes for reproducible state. |
| **ServiceDependencyGraph** | Maps active local dependencies such as Docker containers or database connections. |
| **SecurePayload** | Encrypts sensitive data within the snapshot before storage or sharing using `cryptography`. |
| **ShareCommand** | Exports the snapshot to a shareable artifact or generates a unique reference ID. |
| **RestoreUtility** | Reconstructs the saved environment state on a remote machine or different local setup. |

## Contributing

We welcome contributions! To contribute to **Dev Snapshot CLI**:

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/amazing-feature`).
3.  Make your changes.
4.  Run tests to ensure compatibility.
5.  Commit your changes (`git commit -m 'Add amazing feature'`).
6.  Push to the branch (`git push origin feature/amazing-feature`).
7.  Submit a Pull Request.

Please ensure all new code is covered by unit tests and adheres to the project's linting standards.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

```text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```