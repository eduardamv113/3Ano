import random
import networkx as nx
from heapq import heappush, heappop
import time
from grafo import CriaGrafo as g
from limitacoes import LimEventos as l
from condicoes_metereologicas import SistemaMeteorologico, VisualizadorMeteorologico
from sistemadistribucao import SistemaDistribuicao
from algoritmos_de_busca import Algoritmos

def main_lim_eventos(grafo):
    # Gerar limitações e eventos aleatórios
    limitacoes, eventos = l.aplicar_limitacoes_eventos_aleatorios(grafo)

    print("Limitações aplicadas:")
    for limitacao in limitacoes:
        print(limitacao)

    print("\nEventos aplicados:")
    for evento in eventos:
        print(evento)

    # Aplicar limitações e eventos
    grafo = l.aplicar_limitacoes_e_eventos(grafo, limitacoes, eventos)

    return grafo

def main_algoritmos(grafo, estatisticas):
    print("Nodos com prioridade 3:")
    nodos_prioridade = [no for no, dados in grafo.nodes(data=True) if dados.get('prioridade') == 3]
    print(nodos_prioridade)

    print("Realizando buscas com algoritmos de procura:")

    inicio = "base"
    tipos_conexao = ["estrada", "rio", "aereo"]

    algoritmos = {
        "Busca em Profundidade": Algoritmos.busca_em_profundidade,
        "Busca em Largura": Algoritmos.busca_em_largura,
        "Dijkstra": Algoritmos.dijkstra,
        "Busca Gulosa": Algoritmos.busca_gulosa,
        "Busca A*": Algoritmos.busca_a_estrela
    }

    melhores_resultados = []

    for tipo in tipos_conexao:
        for nome, algoritmo in algoritmos.items():
            start_time = time.time()
            caminho, distancia, nodos_passados = Algoritmos.caminho_com_prioridade_por_algoritmo(
                grafo, inicio, nodos_prioridade, algoritmo, tipo
            )
            tempo_execucao = time.time() - start_time

            if caminho:
                melhores_resultados.append({
                    "algoritmo": nome,
                    "tipo_conexao": tipo,
                    "caminho": caminho,
                    "distancia": distancia,
                    "nodos_passados": nodos_passados,
                    "tempo_execucao": tempo_execucao
                })

                # Armazenar estatísticas
                if nome not in estatisticas:
                    estatisticas[nome] = {"distancia": [], "nodos": [], "tempo": []}
                estatisticas[nome]["distancia"].append(distancia)
                estatisticas[nome]["nodos"].append(len(nodos_passados))
                estatisticas[nome]["tempo"].append(tempo_execucao)

    if melhores_resultados:
        melhores_resultados.sort(
            key=lambda x: (-len(x["nodos_passados"]), x["distancia"], tipos_conexao.index(x["tipo_conexao"]), x["tempo_execucao"])
        )
        melhor = melhores_resultados[0]

        print("\n=== MELHOR CAMINHO ===")
        print(f"Algoritmo: {melhor['algoritmo']}")
        print(f"Tipo de conexão: {melhor['tipo_conexao']}")
        print(f"Caminho: {melhor['caminho']}")
        print(f"Distância total: {melhor['distancia']}")
        print(f"Nodos de prioridade 3 percorridos: {melhor['nodos_passados']} ({len(melhor['nodos_passados'])}/{len(nodos_prioridade)})")
        print(f"Tempo de execução: {melhor['tempo_execucao']:.6f} segundos")
    else:
        print("\nNenhum caminho válido foi encontrado.")

    melhor = melhores_resultados[0]
    return melhor['caminho'], melhor['tipo_conexao'], nodos_prioridade

def main():

    veiculos = [
        {"id": 1, "tipo": "carrinha", "terreno": "estrada", "localizacao": "base", "capacidade": 300, "suprimentos" : 0, "autonomia": 1000, "autonomia_max":1000},
        {"id": 2, "tipo": "helicóptero", "terreno": "aereo", "localizacao": "base", "capacidade": 400, "suprimentos" : 0, "autonomia": 1000, "autonomia_max":1000},
        {"id": 3, "tipo": "jeep", "terreno": "estrada", "localizacao": "base", "capacidade": 250, "suprimentos" : 0, "autonomia": 1000, "autonomia_max":1000},
        {"id": 4, "tipo": "drone", "terreno": "aereo", "localizacao": "base", "capacidade": 100,  "suprimentos" : 0, "autonomia": 500, "autonomia_max":500},
        {"id": 5, "tipo": "barco", "terreno": "rio", "localizacao": "base", "capacidade": 500, "suprimentos" : 0, "autonomia": 2000, "autonomia_max":2000},
    ]

    suprimentos_total = 1000

    estatisticas = {}

    # Criar grafo completo
    grafo = g.criar_grafo_completo()
    g.imprimir_detalhes_grafo(grafo)
    g.visualizar_grafo(grafo)

    # Inicializar sistema meteorológico com o grafo
    print("A Inicializr sistema meteorológico...")
    sistema_meteo = SistemaMeteorologico()
    sistema_meteo.inicializar_zonas_do_grafo(grafo)
    visualizador = VisualizadorMeteorologico()
    
    # Executar simulação
    for iteracao in range(3):
        print(f"\n=== Dia {iteracao + 1} ===")
        
        sistema_meteo.atualizar_condicoes(grafo)

        visualizador.mostrar_condicoes(sistema_meteo)
        
        # Atualizar grafo com condições e limitações
        grafo = sistema_meteo.atualizar_grafo(grafo)
        print("\n")
        grafo = main_lim_eventos(grafo)

        print("\n")

        # Algoritmos aplicados
        melhor_caminho, melhor_tipo_conexao, nodos_prioridade = main_algoritmos(grafo, estatisticas)
        print("\n")

       # Executar distribuição

        atribuicoes = SistemaDistribuicao.distribuir_suprimentos_com_prioridade(melhor_caminho, veiculos, grafo, melhor_tipo_conexao, nodos_prioridade, suprimentos_total)
        
        print("Atribuições realizadas:")
        for atribuicao in atribuicoes:
            print(f"Veículo {atribuicao['veiculo_id']} foi de {atribuicao['origem']} para {atribuicao['destino']}.")
            print(f"  Distância percorrida: {atribuicao['distancia']}")
            print(f"  Suprimentos entregues: {atribuicao['suprimento_entregue']}")

        print("\n")

    # Conclusão sobre nodos de prioridade 3
    nodos_nao_satisfeitos = [no for no in nodos_prioridade if grafo.nodes[no].get('necessidade', 0) > 0]
    if nodos_nao_satisfeitos:
        print("\n========= CONCLUSÃO =========")
        print("\n")
        print(f"Nodos de prioridade 3 não satisfeitos: {nodos_nao_satisfeitos}")
    else:
        print("\n========= CONCLUSÃO =========")
        print("\n")
        print("Todos os nodos de prioridade 3 foram atendidos.")

    # Calcular médias e exibir resultados finais
    print("\n=== Medias dos Algoritmos ===")

    # Inicializar variáveis para os melhores algoritmos
    melhores_algoritmos = {"distancia": None, "nodos": None, "tempo": None}
    melhores_valores = {"distancia": float('inf'), "nodos": float('-inf'), "tempo": float('inf')}

    for algoritmo, dados in estatisticas.items():
        media_distancia = sum(dados["distancia"]) / len(dados["distancia"])
        media_nodos = sum(dados["nodos"]) / len(dados["nodos"])
        media_tempo = sum(dados["tempo"]) / len(dados["tempo"])
        
        print(f"Algoritmo: {algoritmo}")
        print(f"  Distância - media: {media_distancia:.2f}")
        print(f"  Nodos de prioridade 3 percorridos - media: {media_nodos:.2f}")
        print(f"  Tempo médio de execução - media: {media_tempo:.6f} segundos")
        
        # Determinar os melhores algoritmos
        if media_distancia < melhores_valores["distancia"]:
            melhores_valores["distancia"] = media_distancia
            melhores_algoritmos["distancia"] = algoritmo
        elif media_distancia == melhores_valores["distancia"]:
            # Desempate baseado nos nodos percorridos
            if media_nodos > melhores_valores["nodos"]:
                melhores_algoritmos["distancia"] = algoritmo

        if media_nodos > melhores_valores["nodos"]:
            melhores_valores["nodos"] = media_nodos
            melhores_algoritmos["nodos"] = algoritmo
        elif media_nodos == melhores_valores["nodos"]:
            # Desempate baseado na menor distância
            if media_distancia < melhores_valores["distancia"]:
                melhores_algoritmos["nodos"] = algoritmo

        # Melhor tempo de execução
        if media_tempo < melhores_valores["tempo"]:
            melhores_valores["tempo"] = media_tempo
            melhores_algoritmos["tempo"] = algoritmo

    print("\n=== Melhor Algoritmo por: ===")
    print(f"Melhor algoritmo para menor distância: {melhores_algoritmos['distancia']}")
    print(f"Melhor algoritmo para mais nodos percorridos: {melhores_algoritmos['nodos']}")
    print(f"Melhor algoritmo para menor tempo de execução: {melhores_algoritmos['tempo']}")


if __name__ == "__main__":
    main()

