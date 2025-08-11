
# BGE：RSA+AES 混合加解密工具与 Python 模块

一个既可命令行使用、也可在代码中 import 的混合加密工具。使用 RSA-OAEP(SHA-256) 保护随机 AES-256 会话密钥，再用 AES-GCM 对文件/字节进行机密性与完整性保护。支持（可选）硬件密钥解密（如 YubiKey via PKCS#11）。
# BGE: RSA+AES Hybrid Encryption Tool and Python Module

Hybrid encryption with RSA-OAEP (SHA-256) protecting a random AES-256 session key and AES-GCM for confidentiality and integrity. Usable as a CLI and as an importable module. Optional hardware-key decryption (e.g., YubiKey via PKCS#11).

## Contents

- Features
- Installation
- Quick Start (module and CLI)
- CLI usage
- Hardware key notes
- Safe writes (no empty files)
- License

## Features

- Hybrid crypto: RSA-OAEP(SHA-256) + AES-256-GCM.
- Atomic writes: write to a temp file and atomically replace on success; failures leave no empty/partial outputs.
- RSA key generation: 4096-bit, PEM.
- File and bytes APIs: encrypt/decrypt files and raw bytes.
- Folder encryption: threaded or multiprocessing with optional recursion (software key only).
- Hardware key support: decrypt with hardware private key (via pkcs11-tool). File encryption uses software public key.
- Adaptive chunking: dynamic chunk size by file size.

## Installation

- Python 3.8+
- Dependencies (see `requirements.txt`):
  - core: `cryptography`
  - optional for hardware decryption: `python-pkcs11` and system `pkcs11-tool`
- Default PKCS#11 library path: `/opt/homebrew/lib/libykcs11.dylib`
  - Override via API parameter `pkcs11_lib` or edit `DEFAULT_PKCS11_LIB`.

Install deps:

```bash
pip install -r requirements.txt
```

(Hardware decryption only) Ensure `pkcs11-tool` is installed and your device’s PKCS#11 .dylib is accessible.

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

### CLI

From the repo root:

```bash
python bge.py -h
```

Common examples:

```bash
# Generate key pair (creates mykey_private.pem / mykey_public.pem)
python bge.py --genrsakey -o mykey

# Encrypt with software public key
python bge.py -e -i mykey_public.pem /path/to/file.txt

# Decrypt with software private key
python bge.py -d -i mykey_private.pem /path/to/file.txt.enc

# Decrypt with a hardware private key
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
- `--dir <DIR>`: folder-encrypt mode (software public key only; hardware not implemented)
- `-i`, `--keyfile <PATH>`: key file path
  - use a public key (PEM) for encryption
  - use a private key (PEM) for decryption
  - default public key: `~/.ssh/public_rsa.pem` (if you didn’t specify one and it exists)
- `-k`, `--hardware-key`: use hardware private key for decryption (encryption with HW key not implemented)
- `-o`, `--output <PATH>`: output file/folder path
- `-r`, `--recursive`: recurse subdirs when encrypting a folder
- `-w`, `--workers <N>`: parallel workers (default 4)
- `-m`, `--multiprocessing`: use multiprocessing (good for heavy CPU workloads)
- `--genrsakey`: generate an RSA key pair (must also pass `-o` prefix)

Note: folder encryption does not support hardware keys; hardware encryption for single files is not implemented.

## Hardware key notes

- Supported: decrypt with a hardware private key (uses `pkcs11-tool` to perform RSA-OAEP and recover the AES key).
- Not implemented: encrypting files using a hardware public key.
- Dependencies: `python-pkcs11` (only when using HW features) and the system `pkcs11-tool`.
- PKCS#11 path: default `DEFAULT_PKCS11_LIB = /opt/homebrew/lib/libykcs11.dylib`; override via the API’s `pkcs11_lib`.

## Safe writes (no empty files)

- Both encrypt/decrypt first write to a sibling temp file (`<output>.tmp`) and then `os.replace` to the final path on success.
- If an exception occurs, the temp file is removed so you won’t see empty or corrupt targets.

## License

MIT — see [LICENSE](LICENSE).
## 命令行用法

- `-e`, `--encrypt`：加密（文件或文件夹）
- `-d`, `--decrypt`：解密（文件）
- `--dir <DIR>`：文件夹加密模式（仅软件公钥；硬件未实现）
- `-i`, `--keyfile <PATH>`：密钥文件路径
  - 加密用公钥（PEM）
  - 解密用私钥（PEM）
  - 默认公钥：`~/.ssh/public_rsa.pem`（若存在且你未指定）
- `-k`, `--hardware-key`：使用硬件私钥解密（文件加密暂未实现）
- `-o`, `--output <PATH>`：输出文件/文件夹
- `-r`, `--recursive`：文件夹加密时递归子目录
- `-w`, `--workers <N>`：并行工作线程数（默认 4）
- `-m`, `--multiprocessing`：使用多进程（适合 CPU 负载较高时）
- `--genrsakey`：生成 RSA 密钥对（需同时指定 `-o` 前缀）

注意：文件夹加密不支持硬件密钥；单文件加密的硬件密钥模式尚未实现。

## 硬件密钥说明

- 已支持：使用硬件私钥解密（通过 `pkcs11-tool` 调用 RSA-OAEP 解出 AES key）
- 未实现：使用硬件公钥进行文件加密
- 依赖：`python-pkcs11`（仅在使用硬件功能时需要）与系统的 `pkcs11-tool`
- PKCS#11 库路径：默认 `DEFAULT_PKCS11_LIB = /opt/homebrew/lib/libykcs11.dylib`，可在模块 API 中通过 `pkcs11_lib` 覆盖

## 安全写入（无空文件残留）

- 加密/解密均先写入同目录下的临时文件（`<输出>.tmp`），成功后使用 `os.replace` 原子替换为目标文件。
- 发生异常时会清理临时文件，不会留下空文件或损坏的目标文件。

## 许可

本项目使用 MIT 许可证，详见 [LICENSE](LICENSE)。
