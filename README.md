
# BGE, A RSA-AES File Encryption Tool

A command-line tool for encrypting and decrypting files and folders using a combination of RSA and AES algorithms. It supports both software-based RSA keys and hardware keys (like YubiKey) via PKCS#11 interface.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Generating RSA Key Pair](#generating-rsa-key-pair)
  - [Encrypting a File](#encrypting-a-file)
  - [Decrypting a File](#decrypting-a-file)
  - [Encrypting a Folder](#encrypting-a-folder)
  - [Setting up Alias](#setting-up-alias)
- [Options](#options)
- [Examples](#examples)
- [License](#license)
- [Contact](#contact)

## Features

- **Hybrid Encryption**: Combines RSA and AES encryption for secure file handling.
- **Hardware Key Support**: Option to use hardware keys (e.g., YubiKey) via PKCS#11 for RSA operations.
- **Folder Encryption**: Encrypt all files within a folder, with optional recursive encryption.
- **Parallel Processing**: Utilize multithreading or multiprocessing for faster encryption/decryption of multiple files.
- **Dynamic Chunk Size**: Automatically adjusts chunk size based on file size for optimal performance.
- **RSA Key Generation**: Generate RSA key pairs directly from the command line.
- **Secure Key Handling**: Minimal permissions are set on private key files to enhance security.

## Requirements

- Python 3.6 or higher
- Dependencies:
  - `cryptography`
  - `pkcs11`
- PKCS#11 Library for your hardware key (e.g., YubiKey)
  - Default path: `/opt/homebrew/lib/libykcs11.dylib`
- Optional: `pkcs11-tool` for decrypting with hardware key

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/bge_rsa_aes_file.git
   cd bge_rsa_aes_file
   ```

2. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Ensure PKCS#11 Library is Accessible**

   Make sure the PKCS#11 library for your hardware key is installed and the path is correctly set in the script (default is `/opt/homebrew/lib/libykcs11.dylib`).

## Usage

The script provides multiple functionalities through command-line arguments.


## Setting up Alias

To simplify the command usage, you can set up an alias for the script.

1. Open your shell configuration file (e.g., `~/.bashrc` for Bash or `~/.zshrc` for Zsh).

2. Add the following line to create an alias:

   ```bash
   alias bge='python /path/to/bge_rsa_aes_file.py'
   ```

3. Save the file and run the following command to apply the changes:

   - For Bash:
     ```bash
     source ~/.bashrc
     ```

   - For Zsh:
     ```bash
     source ~/.zshrc
     ```

4. Now you can use the `bge` alias to run the script instead of the full Python command.

### Generating RSA Key Pair

Generate a new RSA key pair and save it to specified files.

```bash
bge --genrsakey -o mykey
```

This will generate `mykey_private.pem` and `mykey_public.pem`.

### Encrypting a File

Encrypt a file using a public RSA key.

```bash
bge -e -i path/to/public_rsa.pem file_to_encrypt.txt
```

### Decrypting a File

Decrypt a file using a private RSA key.

```bash
bge -d -i path/to/private_rsa.pem file_to_decrypt.txt.enc
```

### Encrypting a Folder

Encrypt all files in a folder.

```bash
bge -e --dir path/to/folder -i path/to/public_rsa.pem -o encrypted_folder
```

For recursive encryption:

```bash
bge -e --dir path/to/folder -i path/to/public_rsa.pem -o encrypted_folder -r
```


## Options

- `-e`, `--encrypt`: Encrypt file or folder.
- `-d`, `--decrypt`: Decrypt file.
- `--dir`: Specify a folder to encrypt.
- `-i`, `--keyfile`: Path to RSA key file.
  - Default public key path: `~/.ssh/public_rsa.pem`
- `-k`, `--hardware-key`: Use hardware key for RSA operations.
- `-o`, `--output`: Specify output file or directory.
- `-r`, `--recursive`: Recursively encrypt subdirectories.
- `-w`, `--workers`: Number of worker threads/processes (default: 4).
- `-m`, `--multiprocessing`: Use multiprocessing instead of multithreading.
- `--genrsakey`: Generate an RSA key pair.

## Examples

### Encrypt with Hardware Key

```bash
bge -e -k file_to_encrypt.txt
```

### Decrypt with Hardware Key

```bash
bge -d -k file_to_decrypt.txt.enc
```

### Generate RSA Key Pair with Specific Output Names

```bash
bge --genrsakey -o my_rsa_key
```

### Encrypt Folder with Multithreading

```bash
bge -e --dir path/to/folder -i path/to/public_rsa.pem -w 8
```

### Encrypt Folder with Multiprocessing and Recursive Subdirectories

```bash
bge -e --dir path/to/folder -i path/to/public_rsa.pem -w 8 -m -r
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For issues or feature requests, please open an issue on the [GitHub repository](https://github.com/yourusername/bge_rsa_aes_file).

---
