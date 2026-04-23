import networkx as nx
import random
import matplotlib.pyplot as plt


# Tipos de Limitações
class TipoLimitacao:
    ESTRADABLOQUEADA = "estrada_bloqueada"  # Inacessível a estrada
    MANIFESTACAO = "manifestacao"  # Inacessível a estrada
    DESMORONAMENTO = "desmoronamento"  # Inacessível a estrada
    TEMPESTADE = "tempestade"  # Inacessível a via aérea
    DESLIZAMENTO = "deslizamento_terra"  # Inacessível a rio
    DESCONHECIDO = "desconhecido"  # Inacessível a todos
    OBRAS = "obras_estrada"  # Inacessível a estrada

# Tipos de Eventos
class TipoEvento:
    TRANSITO = "trafego_intenso"  # 2.0 estrada
    ACIDENTE = "acidente"  # 2.5 estrada
    OBRALIGEIRA = "obra_ligeira"  # 1.5 estrada
    DESFILE = "desfile"  # 1.7 estrada
    MARE = "mare_forte"  # 1.5 rio
    VENTO = "vento_forte"  # 1.5 qualquer tipo disponível

class LimEventos:   

    @staticmethod
    def aplicar_limitacoes_e_eventos(grafo, limitacoes, eventos):
        
        def aplica_em_duas_direcoes(func):
            """Decorador para aplicar modificações em ambas as direções da aresta."""
            def wrapper(origem, destino, *args, **kwargs):
                func(origem, destino, *args, **kwargs)
                func(destino, origem, *args, **kwargs)
            return wrapper

        @aplica_em_duas_direcoes
        def aplicar_limitacao(origem, destino, tipo_limitação):
            if grafo.has_edge(origem, destino):
                atributos = grafo.edges[origem, destino]

                if tipo_limitação == TipoLimitacao.TEMPESTADE:
                    if "distancia_aereo" in atributos:
                        atributos["distancia_aereo"] = None
                elif tipo_limitação in [TipoLimitacao.ESTRADABLOQUEADA, TipoLimitacao.MANIFESTACAO, TipoLimitacao.DESMORONAMENTO, TipoLimitacao.OBRAS]:
                    if atributos.get("tipo") in ["estrada", "ambas"]:
                        if atributos["tipo"] == "ambas":
                            atributos["tipo"] = "rio"
                            atributos["distancia_estrada"] = None
                        else:
                            grafo.remove_edge(origem, destino)
                elif tipo_limitação == TipoLimitacao.DESLIZAMENTO:
                    if atributos.get("tipo") in ["rio", "ambas"]:
                        if atributos["tipo"] == "ambas":
                            atributos["tipo"] = "estrada"
                            atributos["distancia_rio"] = None
                        else:
                            grafo.remove_edge(origem, destino)

        @aplica_em_duas_direcoes
        def aplicar_evento(origem, destino, tipo_evento, fator_custo):
            if grafo.has_edge(origem, destino):
                atributos = grafo.edges[origem, destino]

                if tipo_evento in [TipoEvento.TRANSITO, TipoEvento.ACIDENTE, TipoEvento.OBRALIGEIRA, TipoEvento.DESFILE] and atributos.get("tipo") in ["estrada", "ambas"]:
                    atributos["distancia_estrada"] *= fator_custo
                elif tipo_evento == TipoEvento.MARE and atributos.get("tipo") in ["rio", "ambas"]:
                    atributos["distancia_rio"] *= fator_custo
                elif tipo_evento == TipoEvento.VENTO:
                    for tipo in ["distancia_estrada", "distancia_rio", "distancia_aereo"]:
                        if tipo in atributos and atributos[tipo] is not None:
                            atributos[tipo] *= fator_custo

        # Aplica limitações geográficas
        for limitacao in limitacoes:
            origem = limitacao["origem"]
            destino = limitacao["destino"]
            tipo_limitação = limitacao["tipo"]
            aplicar_limitacao(origem, destino, tipo_limitação)

        # Aplica eventos dinâmicos que afetam custos
        for evento in eventos:
            origem = evento["origem"]
            destino = evento["destino"]
            tipo_evento = evento["tipo"]
            fator_custo = evento.get("fator_custo", 1.0)
            aplicar_evento(origem, destino, tipo_evento, fator_custo)

        return grafo

    @staticmethod
    def aplicar_limitacoes_eventos_aleatorios(grafo):

        limitacoes = []
        eventos = []

        # Tipos de limitações e eventos disponíveis
        tipos_limitacoes = {
            TipoLimitacao.ESTRADABLOQUEADA: ["estrada", "ambas"],
            TipoLimitacao.MANIFESTACAO: ["estrada", "ambas"],
            TipoLimitacao.DESMORONAMENTO: ["estrada", "ambas"],
            TipoLimitacao.OBRAS: ["estrada", "ambas"],
            TipoLimitacao.DESLIZAMENTO: ["rio", "ambas"],
            TipoLimitacao.TEMPESTADE: ["rio", "estrada", "ambas"]
        }
        tipos_eventos = {
            TipoEvento.TRANSITO: (2.0, ["estrada", "ambas"]),
            TipoEvento.ACIDENTE: (2.5, ["estrada", "ambas"]),
            TipoEvento.OBRALIGEIRA: (1.5, ["estrada", "ambas"]),
            TipoEvento.DESFILE: (1.7, ["estrada", "ambas"]),
            TipoEvento.MARE: (1.5, ["rio", "ambas"]),
            TipoEvento.VENTO: (1.5, ["estrada", "rio", "ambas"])
        }

        # Gerar limitações aleatórias para cada tipo
        for tipo, conexoes_validas in tipos_limitacoes.items():
            for _ in range(random.randint(0, 3)):
                origem, destino, atributos = random.choice([
                    (u, v, d) for u, v, d in grafo.edges(data=True) if d.get("tipo") in conexoes_validas
                ])
                limitacoes.append({"origem": origem, "destino": destino, "tipo": tipo})

        # Gerar eventos aleatórios para cada tipo
        for tipo, (fator_custo, conexoes_validas) in tipos_eventos.items():
            for _ in range(random.randint(1, 5)):
                origem, destino, atributos = random.choice([
                    (u, v, d) for u, v, d in grafo.edges(data=True) if d.get("tipo") in conexoes_validas
                ])
                eventos.append({"origem": origem, "destino": destino, "tipo": tipo, "fator_custo": fator_custo})

        return limitacoes, eventos

def main():
    grafo = nx.DiGraph()

    # Adicionar nós
    grafo.add_node("base", tipo="base")
    grafo.add_node("cidade1", tipo="cidade")
    grafo.add_node("cidade2", tipo="cidade")
    grafo.add_node("freguesia1", tipo="freguesia")
    grafo.add_node("freguesia2", tipo="freguesia")

    # Adicionar arestas com tipos e distâncias
    grafo.add_edge("base", "cidade1", tipo="estrada", distancia_estrada=50, distancia_aereo=60)
    grafo.add_edge("base", "cidade2", tipo="rio", distancia_rio=70, distancia_aereo=80)
    grafo.add_edge("cidade1", "freguesia1", tipo="estrada", distancia_estrada=20, distancia_aereo=30)
    grafo.add_edge("cidade2", "freguesia2", tipo="rio", distancia_rio=40, distancia_aereo=50)
    grafo.add_edge("freguesia1", "freguesia2", tipo="ambas", distancia_estrada=25, distancia_rio=35, distancia_aereo=45)

    # Gerar limitações e eventos aleatórios
    limitacoes, eventos = LimEventos.aplicar_limitacoes_eventos_aleatorios(grafo)

    print("Limitações aplicadas:")
    for limitacao in limitacoes:
        print(limitacao)

    print("\nEventos aplicados:")
    for evento in eventos:
        print(evento)

    # Aplicar limitações e eventos
    grafo = LimEventos.aplicar_limitacoes_e_eventos(grafo, limitacoes, eventos)

    print("\nConexões atualizadas:")
    for origem, destino, atributos in grafo.edges(data=True):
        print(f"Conexão: {origem} -> {destino}, Atributos: {atributos}")

if __name__ == "__main__":
    main()