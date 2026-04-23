##programa cesar.py 

import sys




def preproc(str):
    """Converte letras em maiúsculas e filtra caracteres não-alfabéticos"""
    l = []
    for c in str:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def cesar_enc(texto, chave):
    """Cifra o texto usando a cifra de César"""
    # Calcular o deslocamento baseado na chave (A=0, B=1, ..., Z=25)
    deslocamento = ord(chave) - ord('A')
    
    resultado = []
    for c in texto:
        # Converter caractere para número (A=0, B=1, ..., Z=25)
        pos = ord(c) - ord('A')
        # Aplicar deslocamento com wrap-around
        nova_pos = (pos + deslocamento) % 26
        # Converter de volta para caractere
        resultado.append(chr(nova_pos + ord('A')))
    
    return "".join(resultado)

def cesar_dec(texto, chave):
    """Decifra o texto usando a cifra de César"""
    # Calcular o deslocamento baseado na chave (A=0, B=1, ..., Z=25)
    deslocamento = ord(chave) - ord('A')
    
    resultado = []
    for c in texto:
        # Converter caractere para número (A=0, B=1, ..., Z=25)
        pos = ord(c) - ord('A')
        # Aplicar deslocamento inverso com wrap-around
        nova_pos = (pos - deslocamento) % 26
        # Converter de volta para caractere
        resultado.append(chr(nova_pos + ord('A')))
    
    return "".join(resultado)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python3 cesar.py <enc|dec> <chave A-Z> <mensagem>")
        sys.exit(1)
    
    operacao = sys.argv[1]
    chave = sys.argv[2].upper()
    mensagem = sys.argv[3]
    
    # Validar chave
    if len(chave) != 1 or not chave.isalpha():
        print("Erro: A chave deve ser uma única letra (A-Z)")
        sys.exit(1)
    
    # Pré-processar a mensagem
    texto_limpo = preproc(mensagem)
    
    # Executar operação
    if operacao == "enc":
        resultado = cesar_enc(texto_limpo, chave)
        print(resultado)
    elif operacao == "dec":
        resultado = cesar_dec(texto_limpo, chave)
        print(resultado)
    else:
        print("Erro: Operação deve ser 'enc' ou 'dec'")
        sys.exit(1)


