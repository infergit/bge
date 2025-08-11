import argparse
import os
import traceback
import logging

from bge_crypto import (
    generate_rsa_keys,
    encrypt_file as module_encrypt_file,
    decrypt_file as module_decrypt_file,
    encrypt_folder as module_encrypt_folder,
    DEFAULT_PKCS11_LIB,
)

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Path to the PKCS11 library
PKCS11_LIB = DEFAULT_PKCS11_LIB
# Default RSA Public Key file path
RSA_default_public_key_path = '~/.ssh/public_rsa.pem'
RSA_default_public_key = os.path.expanduser(RSA_default_public_key_path)

# Define OAEPParams globally for both encryption and decryption
# OAEP_PARAMS = OAEPParams(
#     hash_algorithm=Mechanism.SHA256,  # Specify SHA-256 for hashing
#     mgf=MGF.SHA256,                   # Specify that MGF uses SHA-256
#     source=None                       # No additional label (or use a label if necessary)
# )

def _encrypt_folder_cli(folder_path, public_key_path, output_folder=None, recursive=False, max_workers=4, use_multiprocessing=False):
    try:
        out = module_encrypt_folder(
            folder_path,
            public_key_path,
            output_folder=output_folder,
            recursive=recursive,
            max_workers=max_workers,
            use_multiprocessing=use_multiprocessing,
        )
        print(f"Folder '{folder_path}' successfully encrypted to '{out}'")
    except Exception as e:
        print(f"Errors occurred while encrypting folder '{folder_path}': {e}")

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
            _encrypt_folder_cli(args.dir, args.keyfile, args.output, args.recursive, args.workers, args.multiprocessing)
    elif args.genrsakey:
        priv, pub = generate_rsa_keys(args.output)
        print(f"RSA keys saved to '{priv}' and '{pub}'")
    elif args.encrypt:
        if args.hardware_key:
            raise NotImplementedError("Encryption file with hardware key is not yet implemented.")
            # encrypt_file_rsa_aes(args.file, args.output, use_hardware_key=True)
        else:
            out = module_encrypt_file(args.file, args.output, public_key_path=args.keyfile)
            print(f"File '{args.file}' successfully encrypted to '{out}'")
    elif args.decrypt:
        if args.hardware_key:
            out = module_decrypt_file(args.file, output_path=args.output, use_hardware_key=True)
            print(f"File '{args.file}' successfully decrypted to '{out}'")
        else:
            out = module_decrypt_file(args.file, output_path=args.output, private_key_path=args.keyfile)
            print(f"File '{args.file}' successfully decrypted to '{out}'")
    else:
        parser.print_help()

if __name__ == '__main__':
    main()