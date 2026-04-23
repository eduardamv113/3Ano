import random
from enum import Enum
import networkx as nx
from typing import Dict, List, Tuple

class CondicaoMeteorologica(Enum):
    SOL = "sol"
    CHUVA = "chuva"
    NEVE = "neve"
    TEMPESTADE = "tempestade"
    NEVOA = "nevoa"
    VENTO_FORTE = "vento_forte"
    GRANIZO = "granizo"

class SistemaMeteorologico:
    def __init__(self):
        self.impactos = {
            CondicaoMeteorologica.SOL: {"aereo": 1.0, "estrada": 1.0, "rio": 1.0},
            CondicaoMeteorologica.CHUVA: {"aereo": 1.2, "estrada": 1.5, "rio": 1.3},
            CondicaoMeteorologica.NEVE: {"aereo": 1.5, "estrada": 2.0, "rio": 1.0},
            CondicaoMeteorologica.TEMPESTADE: {"aereo": float('inf'), "estrada": 2.0, "rio": 1.8},
            CondicaoMeteorologica.NEVOA: {"aereo": 1.5, "estrada": 1.3, "rio": 1.4},
            CondicaoMeteorologica.VENTO_FORTE: {"aereo": 2.0, "estrada": 1.1, "rio": 1.4},
        }
        self.condicoes_por_zona = {}
        self.valores_originais = {}

    def inicializar_zonas_do_grafo(self, grafo):
        """Inicializa zonas meteorológicas baseadas nas cidades do grafo"""
        # Reset zonas
        self.condicoes_por_zona = {}
        
        # Cada cidade é centro de uma zona meteorológica
        cidades = [n for n, d in grafo.nodes(data=True) if d['tipo'] == 'cidade']
        
        # Associa cada nó à zona (cidade) mais próxima
        for no, dados in grafo.nodes(data=True):
            if dados['tipo'] == 'base':
                zona_mais_proxima = random.choice(cidades)
            elif dados['tipo'] == 'cidade':
                zona_mais_proxima = no
            else:  # freguesia
                # Encontra a cidade conectada
                vizinhos = list(grafo.neighbors(no))
                cidades_conectadas = [v for v in vizinhos if grafo.nodes[v]['tipo'] == 'cidade']
                zona_mais_proxima = cidades_conectadas[0] if cidades_conectadas else random.choice(cidades)
            
            # Atualiza o nó com sua zona
            grafo.nodes[no]['zona'] = zona_mais_proxima
            
            # Inicializa condição meteorológica da zona
            self.condicoes_por_zona[zona_mais_proxima] = CondicaoMeteorologica.SOL

        # Salvar valores originais das arestas
        self.valores_originais = {
            (u, v): {
                'distancia_aereo': data.get('distancia_aereo'),
                'distancia_estrada': data.get('distancia_estrada'),
                'distancia_rio': data.get('distancia_rio')
            }
            for u, v, data in grafo.edges(data=True)
        }

    def atualizar_grafo(self, grafo):
        """Atualiza o grafo com impactos das condições meteorológicas"""
        for (origem, destino), valores in self.valores_originais.items():
            if origem not in grafo or destino not in grafo[origem]:
                continue

            grafo[origem][destino]['distancia_aereo'] = valores['distancia_aereo']
            grafo[origem][destino]['distancia_estrada'] = valores['distancia_estrada']
            grafo[origem][destino]['distancia_rio'] = valores['distancia_rio']

            zona_origem = grafo.nodes[origem].get('zona')
            if not zona_origem:
                continue

            condicao = self.get_condicao_zona(zona_origem)
            impactos = self.impactos[condicao]

            if 'distancia_aereo' in grafo[origem][destino] and grafo[origem][destino]['distancia_aereo'] is not None:
                grafo[origem][destino]['distancia_aereo'] *= impactos['aereo']
            if 'distancia_estrada' in grafo[origem][destino] and grafo[origem][destino]['distancia_estrada'] is not None:
                grafo[origem][destino]['distancia_estrada'] *= impactos['estrada']
            if 'distancia_rio' in grafo[origem][destino] and grafo[origem][destino]['distancia_rio'] is not None:
                grafo[origem][destino]['distancia_rio'] *= impactos['rio']

        return grafo

    def atualizar_condicoes(self, grafo):
        """Atualiza as condições meteorológicas para cada zona"""
        for zona in self.condicoes_por_zona:
            condicao_atual = self.condicoes_por_zona[zona]
            nova_condicao = self.gerar_nova_condicao(condicao_atual)
            self.condicoes_por_zona[zona] = nova_condicao
        
        self.atualizar_grafo(grafo)

    def gerar_nova_condicao(self, condicao_atual: CondicaoMeteorologica) -> CondicaoMeteorologica:
        """Gera uma nova condição meteorológica baseada na atual"""
        probabilidades = {
            CondicaoMeteorologica.SOL: {
                CondicaoMeteorologica.SOL: 0.5,
                CondicaoMeteorologica.CHUVA: 0.3,
                CondicaoMeteorologica.NEVOA: 0.2
            },
            CondicaoMeteorologica.CHUVA: {
                CondicaoMeteorologica.SOL: 0.2,
                CondicaoMeteorologica.CHUVA: 0.3,
                CondicaoMeteorologica.TEMPESTADE: 0.2,
                CondicaoMeteorologica.NEVE: 0.1,
                CondicaoMeteorologica.NEVOA: 0.1
            },
            CondicaoMeteorologica.NEVE: {
                CondicaoMeteorologica.CHUVA: 0.3,
                CondicaoMeteorologica.NEVE: 0.2,
                CondicaoMeteorologica.TEMPESTADE: 0.5
            },
            CondicaoMeteorologica.TEMPESTADE: {
                CondicaoMeteorologica.NEVE: 0.3,
                CondicaoMeteorologica.TEMPESTADE: 0.5,
                CondicaoMeteorologica.SOL: 0.2
            },
            CondicaoMeteorologica.NEVOA: {
                CondicaoMeteorologica.TEMPESTADE: 0.2,
                CondicaoMeteorologica.NEVOA: 0.3,
                CondicaoMeteorologica.SOL: 0.3,
                CondicaoMeteorologica.CHUVA: 0.2
            }
        }
        opcoes = list(probabilidades[condicao_atual].keys())
        pesos = list(probabilidades[condicao_atual].values())
        return random.choices(opcoes, weights=pesos)[0]

    def get_condicao_zona(self, zona: str) -> CondicaoMeteorologica:
        """Retorna a condição meteorológica atual de uma zona"""
        return self.condicoes_por_zona.get(zona, CondicaoMeteorologica.SOL)

class VisualizadorMeteorologico:
    @staticmethod
    def mostrar_condicoes(sistema_meteorologico):
        """Mostra condições atuais por zona"""
        print("\n=== Condições Meteorológicas por Zona ===")
        for zona, condicao in sistema_meteorologico.condicoes_por_zona.items():
            print(f"Zona {zona}: {condicao.value}")
    
    @staticmethod
    def mostrar_impactos_zona(sistema_meteorologico, zona):
        """Mostra impactos da condição atual em uma zona específica"""
        condicao = sistema_meteorologico.get_condicao_zona(zona)
        impactos = sistema_meteorologico.impactos[condicao]
        print(f"\nImpactos nos transportes para Zona {zona} ({condicao.value}):")
        for tipo, fator in impactos.items():
            if fator == float('inf'):
                status = "BLOQUEADO"
            else:
                status = f"Fator de impacto: {fator}"
            print(f"{tipo.capitalize()}: {status}")
            