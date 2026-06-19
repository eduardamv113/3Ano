#!/usr/bin/env python3
# Authenticated encryption using AES-CTR with HMAC-SHA256
# Construction: Encrypt-then-MAC pattern for proven security

import os
import sys
import getpass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CIPHER_KEY_SIZE = 32
AUTH_KEY_SIZE = 32
TOTAL_KEY_MATERIAL = CIPHER_KEY_SIZE + AUTH_KEY_SIZE
COUNTER_SIZE = 16
RANDOM_SALT_SIZE = 16
AUTH_TAG_SIZE = 32
KDF_ITERATIONS = 480_000

def derive_encryption_keys(pwd: bytes, entropy: bytes) -> tuple[bytes, bytes]:
    """Derive cipher and authentication keys from password using PBKDF2."""
    key_derivation = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=TOTAL_KEY_MATERIAL,
        salt=entropy,
        iterations=KDF_ITERATIONS,
    )
    derived_material = key_derivation.derive(pwd)
    cipher_key = derived_material[:CIPHER_KEY_SIZE]
    auth_key = derived_material[CIPHER_KEY_SIZE:]
    return cipher_key, auth_key


def process_encryption(filepath: str) -> None:
    """Encrypt file with AES-CTR and compute authentication tag."""
    user_pwd = getpass.getpass("Pass-phrase: ").encode()
    
    with open(filepath, "rb") as src:
        raw_data = src.read()
    
    random_salt = os.urandom(RANDOM_SALT_SIZE)
    random_counter = os.urandom(COUNTER_SIZE)
    cipher_k, auth_k = derive_encryption_keys(user_pwd, random_salt)
    
    stream_cipher = Cipher(algorithms.AES(cipher_k), modes.CTR(random_counter))
    encryptor_obj = stream_cipher.encryptor()
    encrypted_data = encryptor_obj.update(raw_data) + encryptor_obj.finalize()
    
    auth_hash = hmac.HMAC(auth_k, hashes.SHA256())
    auth_hash.update(random_salt + random_counter + encrypted_data)
    authentication_tag = auth_hash.finalize()
    
    output_name = f"{filepath}.enc"
    with open(output_name, "wb") as dst:
        dst.write(random_salt + random_counter + encrypted_data + authentication_tag)
    
    print(f"[OK] Ficheiro cifrado e autenticado: {output_name}")


def process_decryption(filepath: str) -> None:
    """Verify authentication and decrypt file with AES-CTR."""
    user_pwd = getpass.getpass("Pass-phrase: ").encode()
    
    with open(filepath, "rb") as src:
        ciphertext_bundle = src.read()
    
    required_min_bytes = RANDOM_SALT_SIZE + COUNTER_SIZE + AUTH_TAG_SIZE
    if len(ciphertext_bundle) < required_min_bytes:
        raise ValueError("Criptograma inválido: tamanho insuficiente para salt, NONCE e TAG.")
    
    extracted_salt = ciphertext_bundle[:RANDOM_SALT_SIZE]
    extracted_counter = ciphertext_bundle[RANDOM_SALT_SIZE:RANDOM_SALT_SIZE + COUNTER_SIZE]
    received_tag = ciphertext_bundle[-AUTH_TAG_SIZE:]
    actual_ciphertext = ciphertext_bundle[RANDOM_SALT_SIZE + COUNTER_SIZE:-AUTH_TAG_SIZE]
    
    cipher_k, auth_k = derive_encryption_keys(user_pwd, extracted_salt)
    
    auth_verification = hmac.HMAC(auth_k, hashes.SHA256())
    auth_verification.update(extracted_salt + extracted_counter + actual_ciphertext)
    try:
        auth_verification.verify(received_tag)
    except InvalidSignature as sig_error:
        raise ValueError("Falha de autenticacao: MAC invalido.") from sig_error
    
    stream_cipher = Cipher(algorithms.AES(cipher_k), modes.CTR(extracted_counter))
    decryptor_obj = stream_cipher.decryptor()
    recovered_plaintext = decryptor_obj.update(actual_ciphertext) + decryptor_obj.finalize()
    
    output_name = f"{filepath}.dec"
    with open(output_name, "wb") as dst:
        dst.write(recovered_plaintext)
    
    print(f"[OK] Ficheiro autenticado e decifrado: {output_name}")


def display_instructions() -> None:
    """Show command syntax and available operations."""
    print("Uso:")
    print("  enc <fich>   -- cifra com AES-CTR e autentica com HMAC")
    print("  dec <fich>   -- verifica HMAC e decifra")

def main() -> None:
    """Handle command-line interface and route to appropriate operation."""
    if len(sys.argv) != 3:
        display_instructions()
        sys.exit(1)
    
    requested_op = sys.argv[1].lower()
    target_file = sys.argv[2]
    
    try:
        if requested_op == "enc":
            process_encryption(target_file)
        elif requested_op == "dec":
            process_decryption(target_file)
        else:
            display_instructions()
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


#python pbenc_aes_ctr_hmac.py enc ficheiro.txt
#python pbenc_aes_ctr_hmac.py dec ficheiro.txt.enc