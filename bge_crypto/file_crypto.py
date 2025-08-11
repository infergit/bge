import os
import stat
import getpass
import subprocess
import logging
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

DEFAULT_PKCS11_LIB = '/opt/homebrew/lib/libykcs11.dylib'

log = logging.getLogger(__name__)


# --- Key helpers ---

def generate_rsa_keys(output_prefix: str) -> Tuple[str, str]:
    """Generate a 4096-bit RSA keypair and save to '<prefix>_private.pem' & '<prefix>_public.pem'.

    Returns (private_path, public_path). Raises FileExistsError if exists.
    """
    private_key_file = f"{output_prefix}_private.pem"
    public_key_file = f"{output_prefix}_public.pem"

    if os.path.exists(private_key_file) or os.path.exists(public_key_file):
        raise FileExistsError(
            f"File '{private_key_file}' or '{public_key_file}' already exists."
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_fd = os.open(
        private_key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR
    )
    with os.fdopen(private_fd, 'wb') as priv_file:
        priv_file.write(private_key)

    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(public_key)

    return private_key_file, public_key_file


def _determine_chunk_size(file_size: int) -> int:
    if file_size <= 10 * 1024 * 1024:
        return 64 * 1024
    if file_size <= 100 * 1024 * 1024:
        return 256 * 1024
    return 1024 * 1024


def _get_rsa_key_from_file(file_path: str, key_type: str = 'public'):
    with open(file_path, 'rb') as key_file:
        key_data = key_file.read()

    if key_type == 'private':
        try:
            return serialization.load_pem_private_key(key_data, password=None)
        except ValueError as e:
            raise ValueError("File does not contain a valid RSA private key.") from e
    elif key_type == 'public':
        try:
            return serialization.load_pem_public_key(key_data)
        except ValueError as e:
            raise ValueError("File does not contain a valid RSA public key.") from e
    else:
        raise ValueError("Invalid key_type. Must be 'public' or 'private'.")


def _get_rsa_key_from_hardware(key_type: str = 'public', pkcs11_lib: Optional[str] = None):
    try:
        import pkcs11  # type: ignore
        from pkcs11 import KeyType, ObjectClass
    except Exception as e:
        raise ImportError("python-pkcs11 is required for hardware key operations. Install it via 'pip install python-pkcs11'.") from e

    lib_path = pkcs11_lib or DEFAULT_PKCS11_LIB
    lib = pkcs11.lib(lib_path)
    token = lib.get_token()
    if key_type == 'public':
        session = token.open()
        public_key = session.get_key(
            object_class=ObjectClass.PUBLIC_KEY,
            key_type=KeyType.RSA,
            id=b'\x03',
        )
        return public_key, session
    elif key_type == 'private':
        pin = getpass.getpass("Enter hardware key PIN: ")
        session = token.open(user_pin=pin)
        private_key = session.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            key_type=KeyType.RSA,
            id=b'\x03',
        )
        return private_key, session, pin
    else:
        raise ValueError("Invalid key type: must be 'public' or 'private'.")


def _decrypt_aes_key_with_pkcs11_tool(enc_aes_key: bytes, pin: str, pkcs11_lib: Optional[str] = None) -> bytes:
    lib_path = pkcs11_lib or DEFAULT_PKCS11_LIB
    pkcs11_command = [
        '/opt/homebrew/bin/pkcs11-tool',
        '--module', lib_path,
        '--id', '03',
        '--decrypt',
        '-m', 'RSA-PKCS-OAEP',
        '--hash-algorithm=sha256',
        '--login',
        '--pin', pin,
    ]
    proc = subprocess.Popen(pkcs11_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(input=enc_aes_key)
    if proc.returncode != 0:
        raise RuntimeError(f"pkcs11-tool failed: {err.decode(errors='ignore')}")
    return out


# --- Bytes API ---

def encrypt_bytes(data: bytes, public_key_path: Optional[str] = None, *, use_hardware_key: bool = False, pkcs11_lib: Optional[str] = None) -> bytes:
    """Encrypt raw bytes using hybrid RSA-OAEP (SHA256) + AES-GCM.

    Output format: [4-byte rsa_len][rsa_cipher][12-byte nonce][ciphertext][16-byte tag]
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")

    # Common path: generate AES key and (if needed) encrypt via RSA
    aes_key = os.urandom(32)
    nonce = os.urandom(12)

    if use_hardware_key:
        # Lazy import pkcs11 constants
        from pkcs11 import Mechanism, MGF  # type: ignore
        rsa_key, session = _get_rsa_key_from_hardware('public', pkcs11_lib)
        try:
            enc_aes_key = rsa_key.encrypt(
                aes_key,
                mechanism=Mechanism.RSA_PKCS_OAEP,
                mechanism_param=(Mechanism.SHA256, MGF.SHA256, None),
            )
        finally:
            session.close()
    else:
        if not public_key_path:
            raise ValueError("public_key_path is required when not using hardware key")
        cipher_rsa = _get_rsa_key_from_file(public_key_path, 'public')
        enc_aes_key = cipher_rsa.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    # AES-GCM encrypt data
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # Pack output blob
    out = bytearray()
    out += len(enc_aes_key).to_bytes(4, 'big')
    out += enc_aes_key
    out += nonce
    out += ciphertext
    out += encryptor.tag
    return bytes(out)


def decrypt_bytes(blob: bytes, private_key_path: Optional[str] = None, *, use_hardware_key: bool = False, pin: Optional[str] = None, pkcs11_lib: Optional[str] = None) -> bytes:
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("blob must be bytes")
    if len(blob) < 4 + 12 + 16:
        raise ValueError("blob too small")

    idx = 0
    enc_len = int.from_bytes(blob[idx:idx+4], 'big'); idx += 4
    if len(blob) < 4 + enc_len + 12 + 16:
        raise ValueError("blob corrupted: lengths invalid")
    enc_aes_key = bytes(blob[idx:idx+enc_len]); idx += enc_len
    nonce = bytes(blob[idx:idx+12]); idx += 12
    tag = bytes(blob[-16:])
    ciphertext = bytes(blob[idx:-16])

    # Recover AES key
    if use_hardware_key:
        if pin is None:
            # Try to get from user if interactive; otherwise error
            pin = getpass.getpass("Enter hardware key PIN: ")
        aes_key = _decrypt_aes_key_with_pkcs11_tool(enc_aes_key, pin, pkcs11_lib)
    else:
        if not private_key_path:
            raise ValueError("private_key_path is required when not using hardware key")
        cipher_rsa = _get_rsa_key_from_file(private_key_path, 'private')
        aes_key = cipher_rsa.decrypt(
            enc_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    decryptor.finalize_with_tag(tag)
    return plaintext


# --- File & folder API ---

def encrypt_file(input_path: str, output_path: Optional[str] = None, *, public_key_path: Optional[str] = None, use_hardware_key: bool = False, pkcs11_lib: Optional[str] = None) -> str:
    if output_path is None:
        output_path = f"{input_path}.enc"
    if os.path.exists(output_path):
        raise FileExistsError(f"Output file '{output_path}' already exists")

    file_size = os.path.getsize(input_path)
    chunk_size = _determine_chunk_size(file_size)

    # Prepare RSA and AES
    aes_key = os.urandom(32)
    nonce = os.urandom(12)

    if use_hardware_key:
        from pkcs11 import Mechanism, MGF  # type: ignore
        rsa_key, session = _get_rsa_key_from_hardware('public', pkcs11_lib)
        try:
            enc_aes_key = rsa_key.encrypt(
                aes_key,
                mechanism=Mechanism.RSA_PKCS_OAEP,
                mechanism_param=(Mechanism.SHA256, MGF.SHA256, None),
            )
        finally:
            session.close()
    else:
        if not public_key_path:
            raise ValueError("public_key_path is required when not using hardware key")
        cipher_rsa = _get_rsa_key_from_file(public_key_path, 'public')
        enc_aes_key = cipher_rsa.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    tmp_path = f"{output_path}.tmp"
    try:
        with open(input_path, 'rb') as f_in, open(tmp_path, 'wb') as f_out:
            f_out.write(len(enc_aes_key).to_bytes(4, 'big'))
            f_out.write(enc_aes_key)
            f_out.write(nonce)

            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                f_out.write(encryptor.update(chunk))

            encryptor.finalize()
            f_out.write(encryptor.tag)

        os.replace(tmp_path, output_path)
        return output_path
    finally:
        # Cleanup temp file on exceptions
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def decrypt_file(input_path: str, output_path: Optional[str] = None, *, private_key_path: Optional[str] = None, use_hardware_key: bool = False, pin: Optional[str] = None, pkcs11_lib: Optional[str] = None) -> str:
    file_size = os.path.getsize(input_path)
    chunk_size = _determine_chunk_size(file_size)

    if output_path is None:
        output_path = input_path[:-4] if input_path.endswith('.enc') else f"{input_path}.dec"
    if os.path.exists(output_path):
        raise FileExistsError(f"Output file '{output_path}' already exists")

    tmp_path = f"{output_path}.tmp"
    try:
        with open(input_path, 'rb') as f_in, open(tmp_path, 'wb') as f_out:
            enc_len_bytes = f_in.read(4)
            if len(enc_len_bytes) != 4:
                raise ValueError("Encrypted file is corrupted or incomplete")
            enc_len = int.from_bytes(enc_len_bytes, 'big')
            enc_aes_key = f_in.read(enc_len)
            nonce = f_in.read(12)

            if use_hardware_key:
                if pin is None:
                    pin = getpass.getpass("Enter hardware key PIN: ")
                aes_key = _decrypt_aes_key_with_pkcs11_tool(enc_aes_key, pin, pkcs11_lib)
            else:
                if not private_key_path:
                    raise ValueError("private_key_path is required when not using hardware key")
                cipher_rsa = _get_rsa_key_from_file(private_key_path, 'private')
                aes_key = cipher_rsa.decrypt(
                    enc_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
            decryptor = cipher.decryptor()

            tag_size = 16
            data_size = file_size - 4 - enc_len - 12 - tag_size
            bytes_read = 0
            while bytes_read < data_size:
                chunk = f_in.read(min(chunk_size, data_size - bytes_read))
                if not chunk:
                    break
                f_out.write(decryptor.update(chunk))
                bytes_read += len(chunk)

            tag = f_in.read(tag_size)
            decryptor.finalize_with_tag(tag)

        os.replace(tmp_path, output_path)
        return output_path
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def encrypt_folder(folder_path: str, public_key_path: str, output_folder: Optional[str] = None, *, recursive: bool = False, max_workers: int = 4, use_multiprocessing: bool = False) -> str:
    """Encrypt all files in a folder to a mirror tree with .enc files. Hardware path not implemented here."""
    from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

    if output_folder is None:
        output_folder = f"{folder_path}_encrypted"
    os.makedirs(output_folder, exist_ok=True)

    tasks = []
    executor_cls = ProcessPoolExecutor if use_multiprocessing else ThreadPoolExecutor
    with executor_cls(max_workers=max_workers) as executor:
        for root, dirs, files in os.walk(folder_path):
            if not recursive:
                dirs.clear()
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(root, folder_path)
                out_dir = os.path.join(output_folder, relative_path)
                os.makedirs(out_dir, exist_ok=True)
                out_file = os.path.join(out_dir, f"{file}.enc")
                tasks.append(executor.submit(encrypt_file, file_path, out_file, public_key_path=public_key_path))

        for task in as_completed(tasks):
            # propagate exceptions early
            task.result()

    return output_folder
