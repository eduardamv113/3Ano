# 1. Contar tokens inteiros com sinal + ou - 
import re

def contar_inteiros_com_sinal(ficheiro):
	with open(ficheiro, 'r', encoding='utf-8') as f:
		conteudo = f.read()
	tokens = conteudo.split()
	padrao = re.compile(r'^[+-]\d+$')
	inteiros = [t for t in tokens if padrao.match(t)]
	return len(inteiros)
	
# 2. Contar tokens que começam com letra minúscula e terminam com número
def contar_tokens_letra_num(ficheiro):
	with open(ficheiro, 'r', encoding='utf-8') as f:
		conteudo = f.read()
	tokens = conteudo.split()
	padrao = re.compile(r'^[a-z].*\d$') # Inicia com minúscula a-z e termina com número 
	tokens_validos = [t for t in tokens if padrao.match(t)]
	return len(tokens_validos)

""""
ou

def contar_inteiros_com_sinal(ficheiro):
    with open(ficheiro, 'r', encoding='utf-8') as f:
        return sum(1 for t in f.read().split() if re.fullmatch(r'[+-]\d+', t))

def contar_tokens_letra_num(ficheiro):
    with open(ficheiro, 'r', encoding='utf-8') as f:
        return sum(1 for t in f.read().split() if re.fullmatch(r'[a-z].*\d', t))
"""


#main

if __name__ == "__main__":
	ficheiro = "tpc1.txt"
	total = contar_inteiros_com_sinal(ficheiro)
	print(f"Começam com números inteiros com sinal: {total}")
	total2 = contar_tokens_letra_num(ficheiro)
	print(f"Começam com minúscula e terminam com número: {total2}")
