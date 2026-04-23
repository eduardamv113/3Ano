##vigenere attack

import sys
from collections import Counter
from cesar import preproc, cesar_dec
from vigenere import vigenere_dec

# Letras mais frequentes em Português (por ordem)
FREQUENTES_PT = ['A', 'E', 'O', 'S', 'I', 'R', 'N', 'T', 'D', 'L']

def analisar_frequencia(fatia):
    """
    Analisa a frequência de letras em uma fatia.
    Retorna uma lista de tuplas (letra, frequência) ordenada por frequência decrescente.
    """
    if not fatia:
        return []
    
    contador = Counter(fatia)
    return contador.most_common()

def descobrir_chave_fatia(fatia):
    """
    Descobre a chave de uma fatia usando análise de frequência.
    Tenta agrupar a letra mais frequente com cada uma das letras mais frequentes em PT.
    Retorna una lista de candidatos (chave_char, score).
    """
    freq = analisar_frequencia(fatia)
    if not freq:
        return []
    
    letra_mais_freq = freq[0][0]  # Letra mais frequente na fatia
    
    candidatos = []
    
    # Tentar agrupar com as letras mais frequentes em Português
    for letra_pt in FREQUENTES_PT:
        # Se a letra mais frequente na fatia é 'letra_mais_freq' e assumimos que é 'letra_pt',
        # então a chave seria a diferença entre elas
        deslocamento = (ord(letra_mais_freq) - ord(letra_pt)) % 26
        chave_char = chr(deslocamento + ord('A'))
        
        # Qualidade do candidato: número de letras frequentes que aparecem
        score = 0
        freq_dict = dict(freq)
        for i, letra in enumerate(FREQUENTES_PT):
            if letra in freq_dict:
                score += (FREQUENTES_PT.index(letra) + 1) * freq_dict[letra]
        
        candidatos.append((chave_char, score))
    
    return candidatos

def calcular_score_frequencia(texto):
    """
    Calcula uma pontuação baseada na frequência de letras portuguesas.
    Maior score = mais similar ao Português.
    """
    contador = Counter(texto)
    score = 0
    
    # Weights para as letras mais frequentes em Português
    weights = {
        'A': 10, 'E': 10, 'O': 9, 'S': 8, 'I': 7, 'R': 7, 'N': 6, 'T': 5, 'D': 5, 'L': 4
    }
    
    for letra, weight in weights.items():
        score += contador.get(letra, 0) * weight
    
    return score

def reconstruir_texto(fatias_decifradas, tamanho_original):
    """
    Reconstrói o texto original a partir das fatias decifradas.
    """
    resultado = [''] * tamanho_original
    num_fatias = len(fatias_decifradas)
    
    for i, fatia in enumerate(fatias_decifradas):
        for j, char in enumerate(fatia):
            pos_original = j * num_fatias + i
            if pos_original < tamanho_original:
                resultado[pos_original] = char
    
    return ''.join(resultado)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Uso: python3 vigenere_attack.py <tamanho_chave> <criptograma> <palavra1> [palavra2] ...")
        sys.exit(1)
    
    tamanho_chave = int(sys.argv[1])
    criptograma = sys.argv[2]
    palavras = sys.argv[3:]  # Lista de palavras a procurar
    
    # Pré-processar o criptograma e as palavras
    texto_cifrado = preproc(criptograma)
    palavras_processadas = [preproc(p) for p in palavras]
    
    # Dividir o criptograma em fatias (uma para cada posição da chave)
    fatias = ['' for _ in range(tamanho_chave)]
    for i, char in enumerate(texto_cifrado):
        fatias[i % tamanho_chave] += char
    
    # Usar análise de frequência para cada fatia
    candidatos_por_fatia = []
    for fatia in fatias:
        # Para cada fatia, obter todos os possíveis deslocamentos
        todas_chaves = []
        for chave_idx in range(26):
            chave_char = chr(chave_idx + ord('A'))
            texto_decifrado = cesar_dec(fatia, chave_char)
            todas_chaves.append((chave_char, texto_decifrado))
        candidatos_por_fatia.append(todas_chaves)
    
    # Testar combinações priorizando as que fazem mais sentido por frequência
    melhor_chave = None
    melhor_texto = None
    melhor_contagem = 0
    melhor_score_freq = -1
    
    # Gerar combinações de forma mais inteligente
    from itertools import product
    for combinacao in product(*[range(26) for _ in range(tamanho_chave)]):
        chave = ''
        fatias_decifradas = []
        
        for i, idx in enumerate(combinacao):
            chave_char, texto_fatia = candidatos_por_fatia[i][idx]
            chave += chave_char
            fatias_decifradas.append(texto_fatia)
        
        # Reconstruir o texto completo
        texto_decifrado = reconstruir_texto(fatias_decifradas, len(texto_cifrado))
        
        # Contar quantas palavras aparecem
        contagem = 0
        for palavra in palavras_processadas:
            if palavra in texto_decifrado:
                contagem += 1
        
        # Calcular score de frequência para desempate
        score_freq = calcular_score_frequencia(texto_decifrado) if contagem > 0 else -1
        
        # Guardar se for melhor (primeiro por contagem, depois por frequência)
        if contagem > melhor_contagem or (contagem == melhor_contagem and contagem > 0 and score_freq > melhor_score_freq):
            melhor_contagem = contagem
            melhor_chave = chave
            melhor_texto = texto_decifrado
            melhor_score_freq = score_freq
            # Se encontramos todas as palavras, continuar verificando para encontrar a melhor por frequência
            if contagem == len(palavras_processadas):
                # Continuar iterando para encontrar a melhor solução com frequência
                continue
    
    # Se encontramos pelo menos uma palavra, imprimir resultado
    if melhor_contagem > 0:
        print(melhor_chave)
        print(melhor_texto)