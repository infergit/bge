# BGE：RSA+AES 混合加解密工具与 Python 模块

使用 RSA-OAEP（SHA-256）保护随机生成的 AES-256 会话密钥，并用 AES-GCM 提供机密性与完整性。既可通过命令行使用，也可在代码中以模块形式导入。支持基于 PKCS#11 的硬件密钥（如 YubiKey）。

想看英文文档？请见 README.md

## 目录

- 功能特性
- 安装
- 快速上手（模块与 CLI）
- 命令行用法
- 硬件密钥说明
- 加密文件格式
- 安全写入（无空文件）
- 许可

## 功能特性

- 混合加密：RSA-OAEP（SHA-256）+ AES-256-GCM。
- 原子写入：先写入临时文件，成功后原子替换；失败不会留下空/半成品文件。
- RSA 密钥生成：4096-bit，PEM。
- 文件与字节 API：支持对文件与原始字节加解密。
- 文件夹加密：线程或多进程，并可选递归（仅支持软件公钥）。
- 硬件密钥支持：单文件加/解密（基于 PKCS#11）。文件夹模式不支持硬件密钥。
- 自适应分块：根据文件大小动态选择分块大小。

## 安装

- Python 3.8+
- 依赖（见 `requirements.txt`）：
  - 核心：`cryptography`
  - 硬件相关（可选）：`python-pkcs11` 与系统 `pkcs11-tool`
- 默认 PKCS#11 库路径：`/opt/homebrew/lib/libykcs11.dylib`
  - 可通过 API 的 `pkcs11_lib` 参数覆盖，或修改 `DEFAULT_PKCS11_LIB`。

安装依赖：

```bash
pip install -r requirements.txt
```

（硬件功能）请确保已安装 `pkcs11-tool` 且你的设备 PKCS#11 动态库可访问。

## 快速上手

### 作为 Python 模块使用

```python
from bge_crypto import (
    generate_rsa_keys,
    encrypt_file, decrypt_file,
    encrypt_bytes, decrypt_bytes,
)

# 1）生成密钥对
priv, pub = generate_rsa_keys("mykey")  # 生成 mykey_private.pem / mykey_public.pem

# 2）文件加/解密（软件密钥）
enc_path = encrypt_file("/path/to/file.txt", public_key_path=pub)
dec_path = decrypt_file(enc_path, private_key_path=priv)

# 3）字节加/解密
blob = encrypt_bytes(b"hello", public_key_path=pub)
plain = decrypt_bytes(blob, private_key_path=priv)
```

硬件私钥解密（需要 pkcs11-tool 与 python-pkcs11；可提供 PIN 或交互式输入）：

```python
from bge_crypto import decrypt_file, DEFAULT_PKCS11_LIB

dec_path = decrypt_file(
    "/path/to/file.txt.enc",
    output_path=None,              # None => 自动推导 .dec
    use_hardware_key=True,         # 使用硬件密钥
    pin=None,                      # None => 交互式提示
    pkcs11_lib=DEFAULT_PKCS11_LIB, # 如需要可覆盖默认值
)
```

硬件公钥加密（单文件）：

```python
from bge_crypto import encrypt_file, DEFAULT_PKCS11_LIB

enc_path = encrypt_file(
    "/path/to/file.txt",
    output_path=None,              # None => 自动推导 .enc
    use_hardware_key=True,         # 使用硬件公钥
    pkcs11_lib=DEFAULT_PKCS11_LIB,
)
```

### CLI

在仓库根目录：

```bash
python bge.py -h
```

常见示例：

```bash
# 生成密钥对（生成 mykey_private.pem / mykey_public.pem）
python bge.py --genrsakey -o mykey
python bge.py --genrsakey mykey          # 也可使用位置参数作为前缀
python bge.py --genrsakey                # 默认为 'rsa_key'

# 使用软件公钥加密
python bge.py -e -i mykey_public.pem /path/to/file.txt

# 使用软件私钥解密
python bge.py -d -i mykey_private.pem /path/to/file.txt.enc

# 使用硬件密钥加密（单文件）
python bge.py -e -k /path/to/file.txt

# 使用硬件密钥解密（单文件）
python bge.py -d -k /path/to/file.txt.enc

# 加密整个文件夹（软件公钥；-r 递归，-w 设置并发，-m 使用多进程）
python bge.py -e --dir /path/to/folder -i mykey_public.pem -w 8
```

小贴士：可添加 zsh 别名：

```bash
alias bge='python /absolute/path/to/bge.py'
```

## 命令行用法

- `-e`, `--encrypt`：加密（文件或文件夹）
- `-d`, `--decrypt`：解密（文件）
- `--dir <DIR>`：文件夹加密模式（仅软件公钥；不支持硬件）
- `-i`, `--keyfile <PATH>`：密钥文件路径
  - 加密用公钥（PEM）
  - 解密用私钥（PEM）
  - 默认公钥：`~/.ssh/public_rsa.pem`（若存在且你未指定）
- `-k`, `--hardware-key`：使用硬件密钥进行单文件加/解密
- `-o`, `--output <PATH>`：输出文件/文件夹路径
- `-r`, `--recursive`：文件夹加密时递归子目录
- `-w`, `--workers <N>`：并行工作线程数（默认 4）
- `-m`, `--multiprocessing`：使用多进程（适合 CPU 负载较高）
- `--genrsakey [PREFIX]`：生成 RSA 密钥对；前缀来自 `-o`、位置参数或默认 `rsa_key`

注意：文件夹加密不支持硬件密钥。

## 硬件密钥说明

- 已支持：基于 PKCS#11 的单文件加/解密；解密底层使用 `pkcs11-tool`。
- 依赖：`python-pkcs11`（仅在使用硬件功能时需要）与系统 `pkcs11-tool`。
- PKCS#11 库路径：默认 `DEFAULT_PKCS11_LIB = /opt/homebrew/lib/libykcs11.dylib`，可在 API 中通过 `pkcs11_lib` 覆盖。

## 加密文件格式

BGE 使用自定义的二进制格式存储加密文件。每个加密文件包含以下结构：

```
[4字节 rsa_len][rsa_cipher][12字节 nonce][ciphertext][16字节 tag]
```

- **4字节 rsa_len**：RSA 加密的 AES 密钥长度（大端序 uint32）
- **rsa_cipher**：RSA-OAEP 加密的 AES-256 会话密钥
- **12字节 nonce**：AES-GCM 随机数
- **ciphertext**：AES-256-GCM 加密的文件内容
- **16字节 tag**：AES-GCM 完整性验证标签

此格式通过 AES-256-GCM 确保机密性，通过 GCM 标签确保真实性，同时使用 RSA-OAEP 加密安全保护 AES 会话密钥。

## 安全写入（无空文件）

- 加密/解密均先写入同目录下的临时文件（`<输出>.tmp`），成功后使用 `os.replace` 原子替换为目标文件。
- 发生异常时会清理临时文件，不会留下空文件或损坏的目标文件。

## 许可

MIT — 详见 [LICENSE](LICENSE)。
