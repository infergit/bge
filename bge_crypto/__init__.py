"""
Reusable RSA+AES crypto utilities.

High-level API:
- generate_rsa_keys(output_prefix) -> (private_path, public_path)
- encrypt_file(input_path, output_path=None, public_key_path=None, use_hardware_key=False, pkcs11_lib=None) -> output_path
- decrypt_file(input_path, output_path=None, private_key_path=None, use_hardware_key=False, pin=None, pkcs11_lib=None) -> output_path
- encrypt_bytes(data: bytes, public_key_path=None, use_hardware_key=False, pkcs11_lib=None) -> bytes
- decrypt_bytes(blob: bytes, private_key_path=None, use_hardware_key=False, pin=None, pkcs11_lib=None) -> bytes

Exceptions are raised on errors instead of printing.
"""

from .file_crypto import (
    generate_rsa_keys,
    encrypt_file,
    decrypt_file,
    encrypt_bytes,
    decrypt_bytes,
    encrypt_folder,
    DEFAULT_PKCS11_LIB,
)

__all__ = [
    "generate_rsa_keys",
    "encrypt_file",
    "decrypt_file",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_folder",
    "DEFAULT_PKCS11_LIB",
]
