##cesar_attack.py 

import sys
from cesar import preproc, cesar_dec


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3 cesar_attack.py <criptograma> <palavra1> [palavra2] ...")
        sys.exit(1)
    
    criptograma = sys.argv[1]
    palavras = sys.argv[2:]  # Lista de palavras a procurar
    
    # Pré-processar o criptograma e as palavras
    texto_cifrado = preproc(criptograma)
    palavras_processadas = [preproc(p) for p in palavras]
    
    # Tentar todas as chaves possíveis (A-Z)
    for chave in range(ord('A'), ord('Z') + 1):
        chave_char = chr(chave)
        texto_decifrado = cesar_dec(texto_cifrado, chave_char)
        
        # Verificar se alguma das palavras está presente no texto decifrado
        for palavra in palavras_processadas:
            if palavra in texto_decifrado:
                # Sucesso! Encontramos a chave
                print(chave_char)
                print(texto_decifrado)
                sys.exit(0)
    
    # Se chegou aqui, não encontrou nenhuma chave válida
    # Não imprime nada (resposta vazia)