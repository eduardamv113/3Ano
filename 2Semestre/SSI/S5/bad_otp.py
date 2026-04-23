##bad_otp.py - One-Time-Pad com PRNG inseguro

"""
Demonstração de como um gerador de números aleatórios inseguro
compromete a segurança do One-Time-Pad.

AVISO: Este programa é apenas para fins educacionais.
Mostra como a qualidade do PRNG é crítica em criptografia.
"""

import sys
import random

def bad_prng(n):
    """
    Gerador de números pseudo-aleatórios INSEGURO.
    
    NUNCA usar em aplicações reais!
    
    Usa apenas 2 bytes de seed, resultando em apenas 2^16 = 65.536
    possibilidades diferentes de sequências, tornando vulnerável a
    ataques de brute force.
    """
    # Seed com apenas 2 bytes = 2^16 possibilidades
    random.seed(random.randbytes(2))
    return random.randbytes(n)

def setup(num_bytes, filename):
    """
    Gera uma chave "aleatória" usando o PRNG inseguro.
    
    A chave gerada é vulnerável porque há apenas 2^16 possíveis chaves!
    """
    # Usar o gerador inseguro em vez de secrets
    key = bad_prng(num_bytes)
    with open(filename, 'wb') as f:
        f.write(key)

def enc(ptxt_file, key_file):
    """Cifra um ficheiro usando a chave OTP via XOR"""
    # Ler o texto-limpo em modo binário
    with open(ptxt_file, 'rb') as f:
        plaintext = f.read()
    
    # Ler a chave em modo binário
    with open(key_file, 'rb') as f:
        key = f.read()
    
    # Verificar se a chave é suficientemente longa
    if len(key) < len(plaintext):
        print(f"Erro: A chave tem apenas {len(key)} bytes, mas o texto tem {len(plaintext)} bytes", file=sys.stderr)
        sys.exit(1)
    
    # Cifrar usando XOR bit a bit
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, key))
    
    # Salvar o criptograma com sufixo .enc
    enc_file = ptxt_file + ".enc"
    with open(enc_file, 'wb') as f:
        f.write(ciphertext)

def dec(ctxt_file, key_file):
    """Decifra um ficheiro usando a chave OTP via XOR"""
    # Ler o texto cifrado em modo binário
    with open(ctxt_file, 'rb') as f:
        ciphertext = f.read()
    
    # Ler a chave em modo binário
    with open(key_file, 'rb') as f:
        key = f.read()
    
    # Verificar se a chave é suficientemente longa
    if len(key) < len(ciphertext):
        print(f"Erro: A chave tem apenas {len(key)} bytes, mas o criptograma tem {len(ciphertext)} bytes", file=sys.stderr)
        sys.exit(1)
    
    # Decifrar usando XOR (XOR é reflexivo: A ⊕ B ⊕ B = A)
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, key))
    
    # Salvar o texto-limpo com sufixo .dec
    dec_file = ctxt_file + ".dec"
    with open(dec_file, 'wb') as f:
        f.write(plaintext)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 bad_otp.py <setup|enc|dec> [argumentos]", file=sys.stderr)
        sys.exit(1)
    
    operacao = sys.argv[1]
    
    if operacao == "setup":
        if len(sys.argv) != 4:
            print("Uso: python3 bad_otp.py setup <num_bytes> <ficheiro_chave>", file=sys.stderr)
            sys.exit(1)
        num_bytes = int(sys.argv[2])
        filename = sys.argv[3]
        setup(num_bytes, filename)
    
    elif operacao == "enc":
        if len(sys.argv) != 4:
            print("Uso: python3 bad_otp.py enc <ficheiro_texto> <ficheiro_chave>", file=sys.stderr)
            sys.exit(1)
        ptxt_file = sys.argv[2]
        key_file = sys.argv[3]
        enc(ptxt_file, key_file)
    
    elif operacao == "dec":
        if len(sys.argv) != 4:
            print("Uso: python3 bad_otp.py dec <ficheiro_criptograma> <ficheiro_chave>", file=sys.stderr)
            sys.exit(1)
        ctxt_file = sys.argv[2]
        key_file = sys.argv[3]
        dec(ctxt_file, key_file)
    
    else:
        print("Erro: Operação deve ser 'setup', 'enc' ou 'dec'", file=sys.stderr)
        sys.exit(1)
