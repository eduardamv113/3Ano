import networkx as nx
from heapq import heappush, heappop
import time

class Algoritmos:

    @staticmethod
    def calcula_distancia_total(grafo, caminho, tipo_conexao):
        """Calcula a distância total de um caminho no grafo para o tipo de conexão especificado."""
        distancia_total = 0
        for i in range(len(caminho) - 1):
            if grafo.has_edge(caminho[i], caminho[i + 1]):
                edge_data = grafo.get_edge_data(caminho[i], caminho[i + 1], default={})
                if tipo_conexao == "aereo":
                    distancia = edge_data.get('distancia_aereo', None)
                else:
                    if edge_data.get('tipo') in ['ambas', tipo_conexao]:
                        distancia = edge_data.get(f'distancia_{tipo_conexao}', None)
                    else:
                        #print(f"Ignorando aresta de tipo diferente de '{tipo_conexao}': ({caminho[i]}, {caminho[i + 1]})")
                        continue

                if distancia is None:
                    #print(f"Ignorando aresta inacessível ({caminho[i]}, {caminho[i + 1]}) para {tipo_conexao}! Dados: {edge_data}")
                    return float('inf')
                '''
                print(f"Aresta válida: ({caminho[i]}, {caminho[i + 1]}), Dados: {edge_data}, Distância: {distancia}")
                print(f"Distância acumulada: {distancia_total}")
                '''
                distancia_total += distancia
            #else:
                #print(f"Erro: Aresta ({caminho[i]}, {caminho[i + 1]}) não encontrada no grafo!")
        return distancia_total

    @staticmethod
    def busca_em_profundidade(grafo, inicio, objetivo, tipo_conexao):
        visitados = set()
        caminho = []

        def dfs(no):
            if no in visitados:
                return False
            visitados.add(no)
            caminho.append(no)

            if no == objetivo:
                return True

            for vizinho in grafo.neighbors(no):
                if vizinho not in visitados and grafo.has_edge(no, vizinho):
                    edge_data = grafo.edges[no, vizinho]
                    if tipo_conexao == "aereo" or edge_data.get('tipo') in ['ambas', tipo_conexao]:
                        if dfs(vizinho):
                            return True

            caminho.pop()
            return False

        dfs(inicio)
        distancia_total = Algoritmos.calcula_distancia_total(grafo, caminho, tipo_conexao)
        return caminho if distancia_total < float('inf') else [], distancia_total

    @staticmethod
    def busca_em_largura(grafo, inicio, objetivo, tipo_conexao):
        fila = [(inicio, [inicio])]
        visitados = set()

        while fila:
            atual, caminho = fila.pop(0)

            if atual in visitados:
                continue
            visitados.add(atual)

            if atual == objetivo:
                distancia_total = Algoritmos.calcula_distancia_total(grafo, caminho, tipo_conexao)
                return caminho if distancia_total < float('inf') else [], distancia_total

            for vizinho in grafo.neighbors(atual):
                if vizinho not in visitados and grafo.has_edge(atual, vizinho):
                    edge_data = grafo.edges[atual, vizinho]
                    if tipo_conexao == "aereo" or edge_data.get('tipo') in ['ambas', tipo_conexao]:
                        fila.append((vizinho, caminho + [vizinho]))

        return [], 0

    @staticmethod
    def dijkstra(grafo, inicio, objetivo, tipo_conexao):
        dist = {no: float('inf') for no in grafo.nodes}
        dist[inicio] = 0
        anterior = {no: None for no in grafo.nodes}
        heap = [(0, inicio)]

        while heap:
            distancia_atual, atual = heappop(heap)

            if atual == objetivo:
                caminho = []
                while atual:
                    caminho.append(atual)
                    atual = anterior[atual]
                caminho.reverse()
                distancia_total = Algoritmos.calcula_distancia_total(grafo, caminho, tipo_conexao)
                return caminho if distancia_total < float('inf') else [], distancia_total

            for vizinho, dados in grafo[atual].items():
                if tipo_conexao == "aereo" or dados.get('tipo') in ['ambas', tipo_conexao]:
                    peso = dados.get(f'distancia_{tipo_conexao}', None) if tipo_conexao != "aereo" else dados.get('distancia_aereo', None)
                    if peso is not None and distancia_atual + peso < dist[vizinho]:
                        dist[vizinho] = distancia_atual + peso
                        anterior[vizinho] = atual
                        heappush(heap, (dist[vizinho], vizinho))

        return [], 0

    @staticmethod
    def busca_gulosa(grafo, inicio, objetivo, tipo_conexao):
        def heuristica(no):
            return grafo.nodes[no].get('necessidade', 1)

        fila = [(heuristica(inicio), inicio, [inicio])]
        visitados = set()

        while fila:
            _, atual, caminho = heappop(fila)

            if atual in visitados:
                continue
            visitados.add(atual)

            if atual == objetivo:
                distancia_total = Algoritmos.calcula_distancia_total(grafo, caminho, tipo_conexao)
                return caminho if distancia_total < float('inf') else [], distancia_total

            for vizinho in grafo.neighbors(atual):
                if vizinho not in visitados and grafo.has_edge(atual, vizinho):
                    edge_data = grafo.edges[atual, vizinho]
                    if tipo_conexao == "aereo" or edge_data.get('tipo') in ['ambas', tipo_conexao]:
                        heappush(fila, (heuristica(vizinho), vizinho, caminho + [vizinho]))

        return [], 0

    @staticmethod
    def busca_a_estrela(grafo, inicio, objetivo, tipo_conexao):
        def heuristica(no):
            return grafo.nodes[no].get('necessidade', 1)

        dist = {no: float('inf') for no in grafo.nodes}
        dist[inicio] = 0
        heap = [(heuristica(inicio), inicio, [inicio])]

        while heap:
            _, atual, caminho = heappop(heap)

            if atual == objetivo:
                distancia_total = Algoritmos.calcula_distancia_total(grafo, caminho, tipo_conexao)
                return caminho if distancia_total < float('inf') else [], distancia_total

            for vizinho, dados in grafo[atual].items():
                if grafo.has_edge(atual, vizinho) and (tipo_conexao == "aereo" or dados.get('tipo') in ['ambas', tipo_conexao]):
                    peso = dados.get(f'distancia_{tipo_conexao}', None) if tipo_conexao != "aereo" else dados.get('distancia_aereo', None)
                    nova_dist = dist[atual] + peso if peso is not None else float('inf')

                    if nova_dist < dist[vizinho]:
                        dist[vizinho] = nova_dist
                        prioridade = nova_dist + heuristica(vizinho)
                        heappush(heap, (prioridade, vizinho, caminho + [vizinho]))

        return [], 0

    @staticmethod
    def caminho_com_prioridade_por_algoritmo(grafo, inicio, nodos_prioridade, algoritmo, tipo_conexao):
        caminho_completo = []
        distancia_total = 0
        nodos_passados = set()

        atual = inicio
        for objetivo in nodos_prioridade:
            # Verifica a janela crítica antes de tentar ir ao nodo
            if grafo.nodes[objetivo].get('janela_critica', float('inf')) < distancia_total:
            #    print(f"Ignorando nodo {objetivo} devido à janela crítica.")
                continue

            caminho, distancia = algoritmo(grafo, atual, objetivo, tipo_conexao)
            if not caminho:
            #    print(f"Aviso: Não foi possível encontrar caminho de {atual} para {objetivo}. Continuando com o próximo nodo.")
                continue

            caminho_completo.extend(caminho[:-1])  # Evita repetir o nodo atual
            distancia_total += distancia
            nodos_passados.update(caminho)
            atual = objetivo

        # Retornar para o início
        caminho, distancia = algoritmo(grafo, atual, inicio, tipo_conexao)
        if caminho:
            caminho_completo.extend(caminho)
            distancia_total += distancia
            nodos_passados.update(caminho)
        #else:
        #    print(f"Aviso: Não foi possível retornar de {atual} para {inicio}.")

        nodos_prioridade_passados = [nodo for nodo in nodos_prioridade if nodo in nodos_passados]
        #print(f"Nodos de prioridade 3 passados: {nodos_prioridade_passados}")
        #print(f"Total: {len(nodos_prioridade_passados)} de {len(nodos_prioridade)}")

        return caminho_completo, distancia_total, nodos_prioridade_passados

if __name__ == "__main__":
    from grafo import CriaGrafo

    grafo = CriaGrafo.criar_grafo_completo()

    print("Nodos com prioridade 3:")
    nodos_prioridade = [no for no, dados in grafo.nodes(data=True) if dados.get('prioridade') == 3]
    print(nodos_prioridade)

    inicio = "base"
    tipos_conexao = ["estrada", "rio", "aereo"]

    algoritmos = {
        "Busca em Profundidade": Algoritmos.busca_em_profundidade,
        "Busca em Largura": Algoritmos.busca_em_largura,
        "Dijkstra": Algoritmos.dijkstra,
        "Busca Gulosa": Algoritmos.busca_gulosa,
        "Busca A*": Algoritmos.busca_a_estrela
    }

    for tipo in tipos_conexao:
        print(f"\n=== Análise para conexões por {tipo.upper()} ===")
        for nome, algoritmo in algoritmos.items():
            print(f"\n{nome} ({tipo}):")
            start_time = time.time()
            caminho, distancia = Algoritmos.caminho_com_prioridade_por_algoritmo(grafo, inicio, nodos_prioridade, algoritmo, tipo)
            print(f"Caminho: {caminho}")
            print(f"Distância total: {distancia}")
            print(f"Tempo de execução: {time.time() - start_time:.6f} segundos")