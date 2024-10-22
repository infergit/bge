import argparse
import os
import stat
import getpass
import traceback
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

import pkcs11
from pkcs11 import KeyType, ObjectClass, Mechanism, MGF

import logging
import subprocess

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Path to the PKCS11 library
PKCS11_LIB = '/opt/homebrew/lib/libykcs11.dylib'
# Default RSA Public Key file path
RSA_default_public_key_path = '~/.ssh/public_rsa.pem'
RSA_default_public_key = os.path.expanduser(RSA_default_public_key_path)

# Define OAEPParams globally for both encryption and decryption
# OAEP_PARAMS = OAEPParams(
#     hash_algorithm=Mechanism.SHA256,  # Specify SHA-256 for hashing
#     mgf=MGF.SHA256,                   # Specify that MGF uses SHA-256
#     source=None                       # No additional label (or use a label if necessary)
# )

user_pin = None

def get_pin():
    global user_pin
    if not user_pin:
        user_pin = getpass.getpass("Please enter the hardware key PIN: ")
    return user_pin

def generate_rsa_keys(output_file):
    private_key_file = f"{output_file}_private.pem"
    public_key_file = f"{output_file}_public.pem"

    if os.path.exists(private_key_file) or os.path.exists(public_key_file):
        raise FileExistsError(f"File '{private_key_file}' or '{public_key_file}' already exists.")

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    private_key = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    public_key = key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Open the private key file with minimal permissions (read/write only for the owner)
    private_fd = os.open(private_key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(private_fd, 'wb') as priv_file:
        priv_file.write(private_key)

    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(public_key)
    print(f"RSA keys saved to '{private_key_file}' and '{public_key_file}'")

def determine_chunk_size(file_size):
    """
    Dynamically determine chunk size based on file size.
    """
    if file_size <= 10 * 1024 * 1024:  # Less than 10MB, use 64KB chunks
        return 64 * 1024
    elif file_size <= 100 * 1024 * 1024:  # Less than 100MB, use 256KB chunks
        return 256 * 1024
    else:  # Larger than 100MB, use 1MB chunks
        return 1024 * 1024

def get_rsa_key_from_hardware(key_type='public'):
    try:
        lib = pkcs11.lib(PKCS11_LIB)
        token = lib.get_token()

        if key_type == 'public':
            session = token.open()
            public_key = session.get_key(
                object_class=ObjectClass.PUBLIC_KEY,
                key_type=KeyType.RSA,
                id=b'\x03'
            )
            return public_key, session
        elif key_type == 'private':
            user_pin = get_pin()
            session = token.open(user_pin=user_pin)
            private_key = session.get_key(
                object_class=ObjectClass.PRIVATE_KEY,
                key_type=KeyType.RSA,
                id=b'\x03'
            )
            return private_key, session
        else:
            raise ValueError(f"Invalid key type: {key_type}, must be 'public' or 'private'.")

    except Exception as e:
        print(f"Error retrieving key from hardware: {e}")
        return None, None


def get_rsa_key_from_file(file_path, key_type='public'):
    with open(file_path, 'rb') as key_file:
        key_data = key_file.read()

    if key_type == 'private':
        try:
            # 尝试加载私钥
            key = serialization.load_pem_private_key(key_data, password=None)
        except ValueError:
            raise ValueError("File does not contain a valid RSA private key.")
    elif key_type == 'public':
        try:
            # 尝试加载公钥
            key = serialization.load_pem_public_key(key_data)
        except ValueError:
            raise ValueError("File does not contain a valid RSA public key.")
    else:
        raise ValueError("Invalid key_type. Must be 'public' or 'private'.")

    return key

def decrypt_aes_key_with_pkcs11_tool(enc_aes_key, pin):
    # Command for pkcs11-tool with the relevant options
    pkcs11_command = [
        '/opt/homebrew/bin/pkcs11-tool', # pkcs11-tool path
        '--module', PKCS11_LIB,
        '--id', '03',  # RSA private key slot in YubiKey
        '--decrypt',
        '-m', 'RSA-PKCS-OAEP',  # Use RSA-OAEP decryption mode
        '--hash-algorithm=sha256',  # Specify SHA-256 as the hash algorithm
        '--login',
        '--pin', pin
    ]

    # Run pkcs11-tool and provide the binary AES key directly as input
    pkcs11_process = subprocess.Popen(pkcs11_command,
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)

    # Communicate the binary AES key to pkcs11-tool via stdin
    pkcs11_output, pkcs11_error = pkcs11_process.communicate(input=enc_aes_key)

    # Check if pkcs11-tool returned an error
    if pkcs11_process.returncode != 0:
        raise Exception(f"Error during pkcs11-tool execution: {pkcs11_error.decode()}")

    # The decrypted AES key will be in pkcs11_output
    return pkcs11_output

def encrypt_file_rsa_aes(file_path, output_file=None, use_hardware_key=False, rsa_key_path=None):
    file_size = os.path.getsize(file_path)
    chunk_size = determine_chunk_size(file_size)

    if output_file is None:
        output_file = f"{file_path}.enc"

    if os.path.exists(output_file):
        print(f"Error: Output file '{output_file}' already exists. Encryption aborted.")
        return

    try:
        # Retrieve RSA public key
        if use_hardware_key:
            rsa_key, session = get_rsa_key_from_hardware('public')
            if rsa_key is None:
                print("Error: Unable to retrieve RSA public key from hardware.")
                return
        else:
            cipher_rsa = get_rsa_key_from_file(rsa_key_path, key_type='public')
            if cipher_rsa is None:
                print(f"Error: Unable to load RSA public key from file '{rsa_key_path}'.")
                return

        # Generate AES key and nonce
        aes_key = os.urandom(32)  # 32 bytes AES key for AES-256
        logging.debug(f'Generated AES key: {aes_key.hex()}')  # 32 bytes AES key for AES-256

        nonce = os.urandom(12)    # 12 bytes nonce for AES-GCM
        logging.debug(f'Generated nonce: {nonce.hex()}')    # 12 bytes nonce for AES-GCM

        # Encrypt AES key using RSA
        if use_hardware_key:
            enc_aes_key = rsa_key.encrypt(
                aes_key,
                mechanism=Mechanism.RSA_PKCS_OAEP,
                mechanism_param=(
                    Mechanism.SHA256,  # Specify that SHA-256 is used for hashing
                    MGF.SHA256,        # Specify MGF1 with SHA-256
                    None
                )
            )
            session.close()
        else:
            enc_aes_key = cipher_rsa.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Specify MGF1 with SHA-256
                    algorithm=hashes.SHA256(),                    # Specify that SHA-256 is used for hashing
                    label=None                   
                )
            )
        logging.debug(f'Encrypted AES key: {enc_aes_key.hex()}, size: {len(enc_aes_key)}') 

        # AES-GCM cipher for file encryption
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        with open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
            # Write encrypted AES key length, encrypted AES key, and nonce
            f_out.write(len(enc_aes_key).to_bytes(4, 'big'))
            f_out.write(enc_aes_key)
            f_out.write(nonce)

            # Encrypt file content in chunks
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                ciphertext = encryptor.update(chunk)
                f_out.write(ciphertext)

            # Finalize encryption and write the tag for GCM
            encryptor.finalize()
            f_out.write(encryptor.tag)

        print(f"File '{file_path}' successfully encrypted to '{output_file}'")

    except Exception as e:
        print(f"Error during encryption: {e}")
        traceback.print_exc()

def decrypt_file_rsa_aes(file_path, output_file=None, use_hardware_key=False, rsa_key_path=None):
    file_size = os.path.getsize(file_path)
    chunk_size = determine_chunk_size(file_size)

    if output_file is None:
        output_file = file_path[:-4] if file_path.endswith('.enc') else f"{file_path}.dec"

    if os.path.exists(output_file):
        print(f"Error: Output file '{output_file}' already exists. Decryption aborted.")
        return

    try:
        # Retrieve RSA private key
        if use_hardware_key: ## Todo: not use this key to decrypt aes key
            rsa_key, session = get_rsa_key_from_hardware('private')
            if rsa_key is None:
                print("Error: Unable to retrieve RSA private key from hardware.")
                return
        else:
            cipher_rsa = get_rsa_key_from_file(rsa_key_path, key_type='private')
            if cipher_rsa is None:
                print(f"Error: Unable to load RSA private key from file '{rsa_key_path}'.")
                return

        with open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
            # Read encrypted AES key length, content, and nonce
            enc_aes_key_len_bytes = f_in.read(4)
            if len(enc_aes_key_len_bytes) != 4:
                print("Error: Encrypted file is corrupted or incomplete.")
                return
            enc_aes_key_len = int.from_bytes(enc_aes_key_len_bytes, 'big')
            logging.debug(f'enc aec key len: {enc_aes_key_len}') 


            enc_aes_key = f_in.read(enc_aes_key_len)
            logging.debug(f'Encrypted AES key: {enc_aes_key.hex()}, size: {enc_aes_key_len}') 

            nonce = f_in.read(12)  # For AES-GCM, the nonce is typically 12 bytes

            # Decrypt AES key
            if use_hardware_key:
                aes_key = decrypt_aes_key_with_pkcs11_tool(enc_aes_key, user_pin)
                # aes_key = rsa_key.decrypt(
                #     enc_aes_key,
                #     mechanism=Mechanism.RSA_PKCS_OAEP,

                #     ### 加上下面的mechanism_param参数反而会报错，去掉后，能正常解密硬件加密的文件 ###
                #     # mechanism_param=(
                #     #     Mechanism.SHA256,  # Specify that SHA-256 is used for hashing
                #     #     MGF.SHA256,        # Specify MGF1 with SHA-256
                #     #     None
                #     # )
                # )
                # session.close()
            else:
                aes_key = cipher_rsa.decrypt(
                    enc_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            logging.debug(f'Decrypted AES key: {aes_key.hex()}')

            # Create AES-GCM decryptor
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()

            # Calculate encrypted data size
            tag_size = 16  # GCM mode uses a 16-byte tag
            data_size = file_size - 4 - enc_aes_key_len - 12 - tag_size

            # Decrypt file content in chunks
            bytes_read = 0
            while bytes_read < data_size:
                chunk = f_in.read(min(chunk_size, data_size - bytes_read))
                if len(chunk) == 0:
                    break
                plaintext = decryptor.update(chunk)
                f_out.write(plaintext)
                bytes_read += len(chunk)

            # Read and verify tag
            tag = f_in.read(tag_size)
            try:
                decryptor.finalize_with_tag(tag)
                print(f"File '{file_path}' successfully decrypted to '{output_file}'")
            except ValueError:
                print("Incorrect key or corrupted file.")

    except Exception as e:
        print(f"Error during decryption: {e}")
        traceback.print_exc()



def encrypt_folder(folder_path, public_key_path, output_folder=None, recursive=False, max_workers=4, use_multiprocessing=False):
    if output_folder is None:
        output_folder = f"{folder_path}_encrypted"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    tasks = []
    executor_cls = ProcessPoolExecutor if use_multiprocessing else ThreadPoolExecutor
    success = True

    with executor_cls(max_workers=max_workers) as executor:
        for root, dirs, files in os.walk(folder_path):
            if not recursive:
                dirs.clear()  # Do not recurse into subdirectories
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(root, folder_path)
                output_dir = os.path.join(output_folder, relative_path)
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)
                output_file = os.path.join(output_dir, f"{file}.enc")
                tasks.append(executor.submit(encrypt_file_rsa_aes, file_path, output_file, False, public_key_path))

        for task in as_completed(tasks):
            try:
                task.result()
            except Exception as e:
                success = False
                print(f"Error: {e}")

    if success:
        print(f"Folder '{folder_path}' successfully encrypted to '{output_folder}'")
    else:
        print(f"Errors occurred while encrypting folder '{folder_path}'")

def main():
    parser = argparse.ArgumentParser(description="AES-RSA Encryption/Decryption Tool")

    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument('-e', '--encrypt', action='store_true', help='Encrypt file or folder using RSA-AES')
    action_group.add_argument('-d', '--decrypt', action='store_true', help='Decrypt file using RSA-AES')

    parser.add_argument('--dir', help='Encrypt all files in folder using RSA-AES')

    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument('-i', '--keyfile', help=f'RSA key file (public key for encryption, private key for decryption), Default:{RSA_default_public_key_path}')
#    key_group.add_argument('-i', '--keyfile', nargs='?', const='~/.ssh/public_rsa.pem', help='RSA key file (public key for encryption, private key for decryption)')
    key_group.add_argument('-k', '--hardware-key', action='store_true', help='Use hardware key for encryption/decryption')

    parser.add_argument('file', nargs='?', help='File to encrypt or decrypt')

    parser.add_argument('-o', '--output', help='Output file or directory for encrypted/decrypted content')

    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively encrypt subdirectories')
    parser.add_argument('-w', '--workers', type=int, default=4, help='Number of worker threads for parallel processing')
    parser.add_argument('-m', '--multiprocessing', action='store_true', help='Use multiprocessing instead of multithreading')

    parser.add_argument('--genrsakey', action='store_true', help='Generate RSA key pair')

    args = parser.parse_args()

    # Parameter validation
    if args.genrsakey and not args.output:
        parser.error("--genrsakey requires -o to specify the output file.")

    if (args.encrypt or args.decrypt):
        if not args.file:
            parser.error("-e or -d requires a file to encrypt or decrypt.")
        if not (args.keyfile or args.hardware_key):
            if args.encrypt and os.path.exists(RSA_default_public_key):
                args.keyfile = RSA_default_public_key
            else:
                parser.error("-e or -d requires either -i (key file) or -k (hardware key).")

    if args.encrypt and args.dir:
        if args.hardware_key:
            raise NotImplementedError("Folder encryption with hardware key is not yet implemented.")
        else:
            encrypt_folder(args.dir, args.keyfile, args.output, args.recursive, args.workers, args.multiprocessing)
    elif args.genrsakey:
        generate_rsa_keys(args.output)
    elif args.encrypt:
        if args.hardware_key:
            raise NotImplementedError("Encryption file with hardware key is not yet implemented.")
            # encrypt_file_rsa_aes(args.file, args.output, use_hardware_key=True)
        else:
            encrypt_file_rsa_aes(args.file, args.output, use_hardware_key=False, rsa_key_path=args.keyfile)
    elif args.decrypt:
        if args.hardware_key:
            decrypt_file_rsa_aes(args.file, output_file=args.output, use_hardware_key=True)
        else:
            decrypt_file_rsa_aes(args.file, output_file=args.output, use_hardware_key=False, rsa_key_path=args.keyfile)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()