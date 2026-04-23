##cifra de vigenere
import sys
from cesar import preproc

def vigenere_enc(texto, chave):
    """Cifra o texto usando a cifra de Vigenère"""
    resultado = []
    chave_len = len(chave)
    
    for i, c in enumerate(texto):
        # Calcular o deslocamento baseado na letra da chave
        deslocamento = ord(chave[i % chave_len]) - ord('A')
        # Converter caractere para número (A=0, B=1, ..., Z=25)
        pos = ord(c) - ord('A')
        # Aplicar deslocamento com wrap-around
        nova_pos = (pos + deslocamento) % 26
        # Converter de volta para caractere
        resultado.append(chr(nova_pos + ord('A')))
    
    return "".join(resultado)

def vigenere_dec(texto, chave):
    """Decifra o texto usando a cifra de Vigenère"""
    resultado = []
    chave_len = len(chave)
    
    for i, c in enumerate(texto):
        # Calcular o deslocamento baseado na letra da chave
        deslocamento = ord(chave[i % chave_len]) - ord('A')
        # Converter caractere para número (A=0, B=1, ..., Z=25)
        pos = ord(c) - ord('A')
        # Aplicar deslocamento inverso com wrap-around
        nova_pos = (pos - deslocamento) % 26
        # Converter de volta para caractere
        resultado.append(chr(nova_pos + ord('A')))
    
    return "".join(resultado)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python3 vigenere.py <enc|dec> <chave> <mensagem>")
        sys.exit(1)
    
    operacao = sys.argv[1]
    chave = sys.argv[2].upper()
    mensagem = sys.argv[3]
    
    # Validar chave (deve ser apenas letras)
    if not chave.isalpha():
        print("Erro: A chave deve conter apenas letras")
        sys.exit(1)
    
    # Pré-processar a mensagem
    texto_limpo = preproc(mensagem)
    
    # Executar operação
    if operacao == "enc":
        resultado = vigenere_enc(texto_limpo, chave)
        print(resultado)
    elif operacao == "dec":
        resultado = vigenere_dec(texto_limpo, chave)
        print(resultado)
    else:
        print("Erro: Operação deve ser 'enc' ou 'dec'")
        sys.exit(1)
