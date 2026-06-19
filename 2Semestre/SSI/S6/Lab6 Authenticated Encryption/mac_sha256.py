#!/usr/bin/env python3
# Message Authentication Code using SHA256 with prefix construction
from cryptography.hazmat.primitives import hashes
import secrets
import sys
import os

KEY_SIZE_BITS = 32  # 256 bits

def initialize_key(keyfile_path: str) -> None:
    """Initialize and persist a new random cryptographic key."""
    random_key = os.urandom(KEY_SIZE_BITS)
    with open(keyfile_path, "wb") as keyfile:
        keyfile.write(random_key)
    print(f"[OK] Chave criada em: {keyfile_path}")

def load_key_from_file(keyfile_path: str) -> bytes:
    """Load and validate cryptographic key from persistent storage."""
    with open(keyfile_path, "rb") as keyfile:
        stored_key = keyfile.read()
    
    if len(stored_key) != KEY_SIZE_BITS:
        raise ValueError(f"Chave inválida: esperado {KEY_SIZE_BITS} bytes, obtido {len(stored_key)} bytes.")
    return stored_key

def calculate_prefix_mac(secret_key: bytes, message: bytes) -> bytes:
    """Compute MAC using prefix construction: HMAC = H(key || message)."""
    hash_obj = hashes.Hash(hashes.SHA256())
    hash_obj.update(secret_key)
    hash_obj.update(message)
    return hash_obj.finalize()

def generate_file_mac(input_file: str, keyfile: str) -> None:
    """Compute and save message authentication code for file."""
    key = load_key_from_file(keyfile)
    
    with open(input_file, "rb") as file_handle:
        file_contents = file_handle.read()
    
    mac_value = calculate_prefix_mac(key, file_contents)
    
    output_path = f"{input_file}.mac"
    with open(output_path, "wb") as mac_file:
        mac_file.write(mac_value)
    
    print(f"[OK] MAC gravado em: {output_path}")

def validate_file_mac(target_file: str, keyfile: str) -> None:
    """Verify authenticity of file by checking stored MAC against computed value."""
    key = load_key_from_file(keyfile)
    
    with open(target_file, "rb") as file_handle:
        file_contents = file_handle.read()
    
    mac_path = f"{target_file}.mac"
    with open(mac_path, "rb") as mac_file:
        persisted_mac = mac_file.read()
    
    fresh_mac = calculate_prefix_mac(key, file_contents)
    is_valid = secrets.compare_digest(fresh_mac, persisted_mac)
    print(f"[OK] Verificação do MAC: {'PASS' if is_valid else 'FAIL'}")

def show_usage() -> None:
    """Display command-line interface documentation."""
    print("Uso:")
    print("  setup <fkey>")
    print("  mac   <fich> <fkey>")
    print("  ver   <fich> <fkey>")


def main() -> None:
    """Parse command-line arguments and execute requested operation."""
    if len(sys.argv) < 2:
        show_usage()
        sys.exit(1)
    
    operation = sys.argv[1].lower()
    
    try:
        if operation == "setup":
            if len(sys.argv) != 3:
                show_usage()
                sys.exit(1)
            initialize_key(sys.argv[2])
        
        elif operation == "mac":
            if len(sys.argv) != 4:
                show_usage()
                sys.exit(1)
            generate_file_mac(sys.argv[2], sys.argv[3])
        
        elif operation == "ver":
            if len(sys.argv) != 4:
                show_usage()
                sys.exit(1)
            validate_file_mac(sys.argv[2], sys.argv[3])
        
        else:
            show_usage()
            sys.exit(1)
    
    except FileNotFoundError as e:
        print(f"[ERRO] Ficheiro não encontrado: {e.filename}")
        sys.exit(1)
    except ValueError as e:
        print(f"[ERRO] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERRO] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


#python mac_sha256.py setup mar.key
#python mac_sha256.py mac ficheiro.txt mar.key
#python mac_sha256.py ver ficheiro.txt mar.key