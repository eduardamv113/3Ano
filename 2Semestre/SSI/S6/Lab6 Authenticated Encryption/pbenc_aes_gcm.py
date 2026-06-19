#!/usr/bin/env python3
# Authenticated encryption using AES-GCM (Galois/Counter Mode)
# GCM provides both confidentiality and authenticity with a single primitive

import os
import sys
import getpass
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ENCRYPTION_KEY_LENGTH = 32
KDF_SALT_LENGTH = 16
GCM_NONCE_LENGTH = 12
GCM_AUTH_TAG_LENGTH = 16
PBKDF2_WORK_FACTOR = 480_000

def expand_password_to_key(password: bytes, salt: bytes) -> bytes:
    """Expand user password to cryptographic key using PBKDF2-SHA256."""
    kdf_instance = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=ENCRYPTION_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_WORK_FACTOR,
    )
    return kdf_instance.derive(password)


def perform_encryption(filepath: str) -> None:
    """Encrypt and authenticate file using AES-GCM-256."""
    user_password = getpass.getpass("Pass-phrase: ").encode()
    
    with open(filepath, "rb") as input_handle:
        plaintext_data = input_handle.read()
    
    random_salt = os.urandom(KDF_SALT_LENGTH)
    random_nonce = os.urandom(GCM_NONCE_LENGTH)
    derived_key = expand_password_to_key(user_password, random_salt)
    
    gcm_cipher = Cipher(algorithms.AES(derived_key), modes.GCM(random_nonce))
    cipher_encryptor = gcm_cipher.encryptor()
    encrypted_data = cipher_encryptor.update(plaintext_data) + cipher_encryptor.finalize()
    authentication_tag = cipher_encryptor.tag
    
    output_filepath = f"{filepath}.enc"
    with open(output_filepath, "wb") as output_handle:
        output_handle.write(random_salt + random_nonce + encrypted_data + authentication_tag)
    
    print(f"[OK] Ficheiro cifrado e autenticado: {output_filepath}")


def perform_decryption(filepath: str) -> None:
    """Verify GCM tag and decrypt authenticated file."""
    user_password = getpass.getpass("Pass-phrase: ").encode()
    
    with open(filepath, "rb") as input_handle:
        encrypted_bundle = input_handle.read()
    
    minimum_required_size = KDF_SALT_LENGTH + GCM_NONCE_LENGTH + GCM_AUTH_TAG_LENGTH
    if len(encrypted_bundle) < minimum_required_size:
        raise ValueError("Criptograma invalido: tamanho insuficiente para salt, nonce e tag.")
    
    stored_salt = encrypted_bundle[:KDF_SALT_LENGTH]
    stored_nonce = encrypted_bundle[KDF_SALT_LENGTH:KDF_SALT_LENGTH + GCM_NONCE_LENGTH]
    stored_tag = encrypted_bundle[-GCM_AUTH_TAG_LENGTH:]
    encrypted_payload = encrypted_bundle[KDF_SALT_LENGTH + GCM_NONCE_LENGTH:-GCM_AUTH_TAG_LENGTH]
    
    recovered_key = expand_password_to_key(user_password, stored_salt)
    
    gcm_cipher = Cipher(algorithms.AES(recovered_key), modes.GCM(stored_nonce, stored_tag))
    cipher_decryptor = gcm_cipher.decryptor()
    
    try:
        decrypted_data = cipher_decryptor.update(encrypted_payload) + cipher_decryptor.finalize()
    except InvalidTag as tag_error:
        raise ValueError("Falha de autenticacao: tag GCM invalida.") from tag_error
    
    output_filepath = f"{filepath}.dec"
    with open(output_filepath, "wb") as output_handle:
        output_handle.write(decrypted_data)
    
    print(f"[OK] Ficheiro autenticado e decifrado: {output_filepath}")


def display_usage() -> None:
    """Show program usage and available commands."""
    print("Uso:")
    print("  enc <fich>   -- cifra e autentica com AES-GCM")
    print("  dec <fich>   -- verifica a tag e decifra")

def main() -> None:
    """Parse arguments and dispatch to encryption or decryption routine."""
    if len(sys.argv) != 3:
        display_usage()
        sys.exit(1)
    
    operation_type = sys.argv[1].lower()
    file_argument = sys.argv[2]
    
    try:
        if operation_type == "enc":
            perform_encryption(file_argument)
        elif operation_type == "dec":
            perform_decryption(file_argument)
        else:
            display_usage()
            sys.exit(1)

	except FileNotFoundError as e:
		print(f"[ERRO] Ficheiro nao encontrado: {e.filename}")
		sys.exit(1)
	except ValueError as e:
		print(f"[ERRO] {e}")
		sys.exit(1)
	except Exception as e:
		print(f"[ERRO] {e}")
		sys.exit(1)


if __name__ == "__main__":
    main()