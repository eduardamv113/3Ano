#!/usr/bin/env python3
# Exploit: Length extension attack against prefix-based SHA256 MAC scheme
# Attacker can forge valid MAC for extended message without knowing the secret key

import sys
import hashpumpy

SECRET_KEY_SIZE = 32
HASH_OUTPUT_BYTES = 32

def print_help() -> None:
    """Display usage information."""
    print("Uso: python mac_sha256_attack.py <fich> <ext>")
    print("  <fich>      -- ficheiro com a mensagem original")
    print("  <fich>.mac  -- ficheiro com o MAC original (deve existir)")
    print("  <ext>       -- texto a acrescentar à mensagem")


def execute_extension_attack() -> None:
    """Perform length extension attack on prefix-MAC scheme."""
    if len(sys.argv) != 3:
        print_help()
        sys.exit(1)
    
    source_file = sys.argv[1]
    extension_text = sys.argv[2].encode("utf-8")
    
    with open(source_file, "rb") as input_file:
        base_message = input_file.read()
    
    mac_source_path = f"{source_file}.mac"
    with open(mac_source_path, "rb") as mac_input:
        original_mac_data = mac_input.read()
    
    if len(original_mac_data) != HASH_OUTPUT_BYTES:
        raise ValueError(f"MAC inválido: esperado {HASH_OUTPUT_BYTES} bytes, obtido {len(original_mac_data)} bytes.")
    
    original_mac_hexstr = original_mac_data.hex()
    base_msg_str = base_message.decode("latin-1")
    ext_str = extension_text.decode("latin-1")
    
    forged_mac_hex, extended_msg = hashpumpy.hashpump(
        original_mac_hexstr,
        base_msg_str,
        ext_str,
        SECRET_KEY_SIZE
    )
    
    if isinstance(extended_msg, str):
        extended_msg = extended_msg.encode("latin-1")
    
    output_msg_path = f"{source_file}.ext"
    with open(output_msg_path, "wb") as output_msg:
        output_msg.write(extended_msg)
    
    output_mac_path = f"{source_file}.ext.mac"
    with open(output_mac_path, "wb") as output_mac:
        output_mac.write(bytes.fromhex(forged_mac_hex))
    
    print(f"[OK] Mensagem estendida gravada em : {output_msg_path}")
    print(f"[OK] MAC forjado gravado em        : {output_mac_path}")
    
    padding_bytes = extended_msg[len(base_message):len(extended_msg) - len(extension_text)]
    print(f"\n[INFO] Padding acrescentado ({len(padding_bytes)} bytes):")
    print("  " + " ".join(f"{b:02x}" for b in padding_bytes))
    print(f"\n[VERIFICAÇÃO] Corra agora:")
    print(f"  python mac_sha256.py ver {output_msg_path} <fkey>")


if __name__ == "__main__":
    try:
        execute_extension_attack()
    except FileNotFoundError as e:
        print(f"[ERRO] Ficheiro não encontrado: {e.filename}")
        sys.exit(1)
    except ValueError as e:
        print(f"[ERRO] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERRO] {e}")
        sys.exit(1)