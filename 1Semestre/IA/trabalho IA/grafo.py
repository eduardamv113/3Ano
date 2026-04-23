import networkx as nx
import random
import matplotlib.pyplot as plt

class CriaGrafo:

    def imprimir_detalhes_grafo(grafo):
        print("\n=== DETALHES DO GRAFO ===")
        print(f"\nTotal de nós: {grafo.number_of_nodes()}")
        print(f"Total de arestas: {grafo.number_of_edges()}\n")
        '''
        print("=== NÓS ===")
        print("Formato: nó -> {tipo, prioridade, necessidade}")
        for no, atributos in sorted(grafo.nodes(data=True)):
            print(f"{no} -> {atributos}")

        print("\n=== CONEXÕES ===")
        print("Formato: (origem, destino) -> {tipo, distâncias}")
        for origem, destino, atributos in sorted(grafo.edges(data=True)):
            print(f"({origem}, {destino}) -> {atributos}")
        '''
        
    def criar_grafo_completo():
        # Inicializa o grafo
        grafo = nx.DiGraph()

        # Adiciona o nó base
        grafo.add_node("base", tipo="base", prioridade=0, necessidade=0)

        # Adiciona as cidades principais
        num_cidades = 10
        cidades = [f"cidade {i}" for i in range(1, num_cidades + 1)]
        for cidade in cidades:
            prioridade = 3 if random.random() < 8/200 else random.randint(0, 2)
            
             # Se a prioridade for 3, criamos janela_critica
            if prioridade == 3:
                grafo.add_node(
                    cidade,
                    tipo="cidade",
                    prioridade=prioridade,
                    necessidade=random.randint(100, 300),
                    janela_critica=random.randint(200, 3000)  # Exemplo: 20~60
                )
            else:
                # Caso não seja prioridade 3, adiciona sem janela_crítica
                grafo.add_node(
                    cidade,
                    tipo="cidade",
                    prioridade=prioridade,
                    necessidade=random.randint(200, 3000)
                )
            
            

            # Conecta a base às cidades principais (sempre com estrada ou ambas)
            distancia = random.randint(30, 100)
            tipo = "ambas" if random.random() < 0.3 else "estrada"
            grafo.add_edge("base", cidade, tipo=tipo, 
                          distancia_estrada=distancia, 
                          distancia_rio=distancia if tipo == "ambas" else None,
                          distancia_aereo=distancia)
            grafo.add_edge(cidade, "base", tipo=tipo, 
                          distancia_estrada=distancia, 
                          distancia_rio=distancia if tipo == "ambas" else None,
                          distancia_aereo=distancia)

        # Adiciona freguesias às cidades
        num_freguesias_totais = 189  # 200 - 1 (base) - 10 (cidades)
        freguesias = []
        freguesias_por_cidade = {}

        for i, cidade in enumerate(cidades, 1):
            num_freguesias = min(random.randint(8, 25), num_freguesias_totais - len(freguesias))
            freguesias_por_cidade[cidade] = []

            for j in range(1, num_freguesias + 1):
                freguesia = f"freguesia {i}_{j}"
                freguesias.append(freguesia)
                freguesias_por_cidade[cidade].append(freguesia)

                prioridade = 3 if random.random() < 15/200 else random.randint(0, 2)
                
                # Se a prioridade for 3, criamos janela_critica
                if prioridade == 3:
                    grafo.add_node(
                        freguesia,
                        tipo="freguesia",
                        prioridade=prioridade,
                        necessidade=random.randint(10, 100),
                        janela_critica=random.randint(200, 3000)  # Exemplo: 20~60
                    )
                else:
                    # Caso não seja prioridade 3, adiciona sem janela_crítica
                    grafo.add_node(
                        freguesia,
                        tipo="freguesia",
                        prioridade=prioridade,
                        necessidade=random.randint(10, 100)
                    )
                

                # Conecta cidade à freguesia (sempre com estrada ou ambas)
                distancia = random.randint(10, 50)
                tipo = "ambas" if random.random() < 0.1 else "estrada"
                grafo.add_edge(cidade, freguesia, tipo=tipo,
                               distancia_estrada=distancia,
                               distancia_rio=distancia if tipo == "ambas" else None,
                               distancia_aereo=distancia)
                grafo.add_edge(freguesia, cidade, tipo=tipo,
                               distancia_estrada=distancia,
                               distancia_rio=distancia if tipo == "ambas" else None,
                               distancia_aereo=distancia)

        # Cria um caminho contínuo de rio
        todas_freguesias = freguesias.copy()
        random.shuffle(todas_freguesias)
        num_freguesias_rio = min(len(todas_freguesias), random.randint(20, 40))
        caminho_rio = todas_freguesias[:num_freguesias_rio]

        for i in range(len(caminho_rio) - 1):
            freguesia_atual = caminho_rio[i]
            proxima_freguesia = caminho_rio[i + 1]

            distancia = random.randint(15, 50)

            if grafo.has_edge(freguesia_atual, proxima_freguesia):
                grafo.edges[freguesia_atual, proxima_freguesia]['tipo'] = 'ambas'
                grafo.edges[freguesia_atual, proxima_freguesia]['distancia_rio'] = distancia
            else:
                grafo.add_edge(freguesia_atual, proxima_freguesia,
                               tipo="rio",
                               distancia_rio=distancia,
                               distancia_aereo=distancia)
            if grafo.has_edge(proxima_freguesia, freguesia_atual):
                grafo.edges[proxima_freguesia, freguesia_atual]['tipo'] = 'ambas'
                grafo.edges[proxima_freguesia, freguesia_atual]['distancia_rio'] = distancia
            else:
                grafo.add_edge(proxima_freguesia, freguesia_atual,
                               tipo="rio",
                               distancia_rio=distancia,
                               distancia_aereo=distancia)

        # Adiciona conexões entre freguesias de cidades diferentes
        for _ in range(10, 30):
            freguesia1 = random.choice(freguesias)
            freguesia2 = random.choice(freguesias)
            distancia = random.randint(20, 100)
            grafo.add_edge(freguesia1, freguesia2, tipo="estrada", distancia_estrada=distancia, distancia_aereo=distancia)
            grafo.add_edge(freguesia2, freguesia1, tipo="estrada", distancia_estrada=distancia, distancia_aereo=distancia)

        return grafo

    def visualizar_grafo(grafo):

        pos = {}

        # Posicionar a base em uma das extremidades
        pos['base'] = (-200, 0)

        # Posicionar cidades aleatoriamente ao redor da base
        cidades = [n for n, d in grafo.nodes(data=True) if d['tipo'] == 'cidade']
        for cidade in cidades:
            pos[cidade] = (random.uniform(-150, 150), random.uniform(-150, 150))

        # Posicionar freguesias próximas às suas cidades
        for cidade in cidades:
            freguesias_da_cidade = [f for f in grafo.neighbors(cidade) if grafo.nodes[f]['tipo'] == 'freguesia']
            for freguesia in freguesias_da_cidade:
                pos[freguesia] = (
                    pos[cidade][0] + random.uniform(-50, 50),
                    pos[cidade][1] + random.uniform(-50, 50)
                )

        # Configurar cores e tamanhos dos nós
        cores = []
        tamanhos = []
        labels = {}
        for no, atributos in grafo.nodes(data=True):
            if atributos['tipo'] == 'base':
                cores.append((1.0, 0.0, 0.0, 0.8))  # Vermelho
                tamanhos.append(1200)
                labels[no] = no
            elif atributos['tipo'] == 'cidade':
                cores.append((0.0, 0.0, 1.0, 0.7))  # Azul
                tamanhos.append(1000)
                labels[no] = no
            elif atributos['tipo'] == 'freguesia':
                cores.append((0.0, 1.0, 0.0, 0.5))  # Verde
                tamanhos.append(300)

        # Desenhar o grafo
        nx.draw(grafo, pos, with_labels=True, labels=labels, node_size=tamanhos, node_color=cores, font_size=8, edge_color="gray")
        plt.title("Grafo com Base, Cidades e Freguesias")
        plt.show()

'''
    grafo = criar_grafo_completo()
    imprimir_detalhes_grafo(grafo)
    visualizar_grafo(grafo)
'''