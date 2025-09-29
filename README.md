
# BGE: RSA+AES Hybrid Encryption Tool and Python Module

Hybrid encryption with RSA-OAEP (SHA-256) protecting a random AES-256 session key and AES-GCM for confidentiality and integrity. Usable as a CLI and as an importable module. Optional hardware-key support via PKCS#11.

Looking for Chinese docs? See README.zh-CN.md

## Contents

- Features
- Installation
- Quick Start (module and CLI)
- CLI usage
- Hardware key notes
- Encrypted file format
- Safe writes (no empty files)
- License

## Features

- Hybrid crypto: RSA-OAEP(SHA-256) + AES-256-GCM.
- Atomic writes: write to a temp file and atomically replace on success; failures leave no empty/partial outputs.
- RSA key generation: 4096-bit, PEM.
- File and bytes APIs: encrypt/decrypt files and raw bytes.
- Folder encryption: threaded or multiprocessing with optional recursion (software key only).
- Hardware key support: encrypt/decrypt single files using a hardware key (via PKCS#11). Folder mode does not support hardware keys.
- Adaptive chunking: dynamic chunk size by file size.

## Installation

- Python 3.8+
- Dependencies (see `requirements.txt`):
  - core: `cryptography`
  - optional for hardware key: `python-pkcs11` and system `pkcs11-tool`
- Default PKCS#11 library path: `/opt/homebrew/lib/libykcs11.dylib`
  - Override via API parameter `pkcs11_lib` or edit `DEFAULT_PKCS11_LIB`.

Install deps:

```bash
pip install -r requirements.txt
```

(Hardware features) Ensure `pkcs11-tool` is installed and your device’s PKCS#11 .dylib is accessible.

## Quick Start

### Import as a Python module

```python
from bge_crypto import (
    generate_rsa_keys,
    encrypt_file, decrypt_file,
    encrypt_bytes, decrypt_bytes,
)

# 1) Generate a key pair
priv, pub = generate_rsa_keys("mykey")  # creates mykey_private.pem / mykey_public.pem

# 2) Encrypt / decrypt a file (software keys)
enc_path = encrypt_file("/path/to/file.txt", public_key_path=pub)
dec_path = decrypt_file(enc_path, private_key_path=priv)

# 3) Encrypt / decrypt bytes
blob = encrypt_bytes(b"hello", public_key_path=pub)
plain = decrypt_bytes(blob, private_key_path=priv)
```

Hardware private key decryption (requires pkcs11-tool and python-pkcs11; provide pin or interactively enter):

```python
from bge_crypto import decrypt_file, DEFAULT_PKCS11_LIB

dec_path = decrypt_file(
    "/path/to/file.txt.enc",
    output_path=None,              # None => auto derive .dec
    use_hardware_key=True,         # use hardware key
    pin=None,                      # None => prompt
    pkcs11_lib=DEFAULT_PKCS11_LIB, # override default if needed
)
```

Hardware key encryption (single file):

```python
from bge_crypto import encrypt_file, DEFAULT_PKCS11_LIB

enc_path = encrypt_file(
    "/path/to/file.txt",
    output_path=None,              # None => auto derives .enc
    use_hardware_key=True,         # use hardware public key
    pkcs11_lib=DEFAULT_PKCS11_LIB,
)
```

### CLI

From the repo root:

```bash
python bge.py -h
```

Common examples:

```bash
# Generate key pair (creates mykey_private.pem / mykey_public.pem)
python bge.py --genrsakey -o mykey
python bge.py --genrsakey mykey          # or positional prefix
python bge.py --genrsakey                # defaults to 'rsa_key'

# Encrypt with software public key
python bge.py -e -i mykey_public.pem /path/to/file.txt

# Decrypt with software private key
python bge.py -d -i mykey_private.pem /path/to/file.txt.enc

# Encrypt with a hardware key (single file)
python bge.py -e -k /path/to/file.txt

# Decrypt with a hardware key (single file)
python bge.py -d -k /path/to/file.txt.enc

# Encrypt an entire folder (software public key; use -r for recursion, -w to set workers, -m for multiprocessing)
python bge.py -e --dir /path/to/folder -i mykey_public.pem -w 8
```

Tip: you can add a shell alias, e.g. for zsh:

```bash
alias bge='python /absolute/path/to/bge.py'
```

## CLI usage

- `-e`, `--encrypt`: encrypt (file or folder)
- `-d`, `--decrypt`: decrypt (file)
- `--dir <DIR>`: folder-encrypt mode (software public key only; hardware not supported)
- `-i`, `--keyfile <PATH>`: key file path
  - use a public key (PEM) for encryption
  - use a private key (PEM) for decryption
  - default public key: `~/.ssh/public_rsa.pem` (if you didn’t specify one and it exists)
- `-k`, `--hardware-key`: use hardware key for single-file encrypt/decrypt
- `-o`, `--output <PATH>`: output file/folder path
- `-r`, `--recursive`: recurse subdirs when encrypting a folder
- `-w`, `--workers <N>`: parallel workers (default 4)
- `-m`, `--multiprocessing`: use multiprocessing (good for heavy CPU workloads)
- `--genrsakey [PREFIX]`: generate an RSA key pair; prefix from `-o`, positional `file`, or default `rsa_key`

Notes:
- Folder encryption does not support hardware keys.

## Hardware key notes

- Supported: encrypt/decrypt single files using a hardware key (via PKCS#11). Decrypt uses pkcs11-tool under the hood.
- Dependencies: `python-pkcs11` (only when using HW features) and the system `pkcs11-tool`.
- PKCS#11 path: default `DEFAULT_PKCS11_LIB = /opt/homebrew/lib/libykcs11.dylib`; override via the API’s `pkcs11_lib`.

## Encrypted File Format

BGE uses a custom binary format for encrypted files. Each encrypted file contains the following structure:

```
[4-byte rsa_len][rsa_cipher][12-byte nonce][ciphertext][16-byte tag]
```

- **4-byte rsa_len**: Length of the RSA-encrypted AES key (big-endian uint32)
- **rsa_cipher**: RSA-OAEP encrypted AES-256 session key
- **12-byte nonce**: Random nonce for AES-GCM
- **ciphertext**: AES-256-GCM encrypted file content
- **16-byte tag**: AES-GCM authentication tag for integrity verification

This format ensures both confidentiality (through AES-256-GCM) and authenticity (through the GCM tag), with the AES session key securely protected by RSA-OAEP encryption.

## Safe writes (no empty files)

- Both encrypt/decrypt first write to a sibling temp file (`<output>.tmp`) and then `os.replace` to the final path on success.
- If an exception occurs, the temp file is removed so you won't see empty or corrupt targets.

## License

MIT — see [LICENSE](LICENSE).
