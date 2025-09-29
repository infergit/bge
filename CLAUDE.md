# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BGE is a Python-based RSA+AES hybrid encryption tool that provides both CLI and library functionality. It supports both software-based keys and hardware keys via PKCS#11.

## Development Setup

### Virtual Environment
Always activate the virtual environment before running Python scripts:
```bash
python -m venv venv
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate     # On Windows
```

### Dependencies
Install dependencies:
```bash
pip install -r requirements.txt
```

For hardware key support, ensure `pkcs11-tool` is installed and the PKCS#11 library is accessible at `/opt/homebrew/lib/libykcs11.dylib`.

## Common Commands

### Running the CLI
```bash
python bge.py -h                                    # Show help
python bge.py --genrsakey mykey                     # Generate RSA keys
python bge.py -e -i public_key.pem file.txt         # Encrypt with software key
python bge.py -d -i private_key.pem file.txt.enc    # Decrypt with software key
python bge.py -e -k file.txt                        # Encrypt with hardware key
python bge.py -d -k file.txt.enc                    # Decrypt with hardware key
```

### Folder encryption (software keys only)
```bash
python bge.py -e --dir /path/to/folder -i public_key.pem -w 8 -r
```

### Testing
No formal test framework is configured. Test manually using the CLI commands above.

## Code Architecture

### Core Structure
- `bge.py`: CLI entry point with argument parsing and command orchestration
- `bge_crypto/`: Core crypto module containing all encryption/decryption logic
  - `__init__.py`: Public API exports
  - `file_crypto.py`: Implementation of all crypto operations

### Key Components

#### Crypto Operations (`bge_crypto/file_crypto.py`)
- **Key Management**: RSA 4096-bit key generation with PEM format
- **Hybrid Encryption**: RSA-OAEP (SHA-256) for AES key protection + AES-256-GCM for data
- **Hardware Key Support**: PKCS#11 integration via `python-pkcs11` and `pkcs11-tool`
- **Atomic File Operations**: Uses temporary files with `os.replace()` for safe writes

#### API Levels
1. **Bytes API**: `encrypt_bytes()`, `decrypt_bytes()` for raw data
2. **File API**: `encrypt_file()`, `decrypt_file()` for individual files
3. **Folder API**: `encrypt_folder()` for batch operations (software keys only)

#### Output Format
Encrypted files use this binary structure:
```
[4-byte rsa_len][rsa_cipher][12-byte nonce][ciphertext][16-byte tag]
```

### Hardware Key Integration
- Uses PKCS#11 for public key operations
- Falls back to `pkcs11-tool` subprocess for private key decryption
- Default library path: `/opt/homebrew/lib/libykcs11.dylib`
- Hardware keys only support single-file operations, not folder encryption

### Performance Features
- **Adaptive Chunking**: Dynamic chunk sizes based on file size
- **Parallel Processing**: Configurable workers with threading or multiprocessing for folder operations
- **Safe Error Handling**: Temporary files are cleaned up on failures

## File Naming Conventions
- Generated keys: `{prefix}_private.pem`, `{prefix}_public.pem`
- Encrypted files: `{original}.enc`
- Decrypted files: `{original}` (strips .enc) or `{original}.dec`

## Security Notes
- Private keys are created with 0o600 permissions
- AES keys are 256-bit with random generation
- Uses cryptographically secure random number generation
- Implements proper OAEP padding with SHA-256