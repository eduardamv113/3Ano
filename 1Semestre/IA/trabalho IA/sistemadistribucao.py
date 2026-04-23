class SistemaDistribuicao:

    @staticmethod
    def encontrar_caminho_para_base(grafo, origem, tipo_conexao):
        from heapq import heappop, heappush

        # Usar Dijkstra para encontrar o caminho mais curto até a base
        distancias = {no: float('inf') for no in grafo.nodes}
        distancias[origem] = 0
        prioridade = [(0, origem)]
        predecessores = {}

        while prioridade:
            distancia_atual, nodo_atual = heappop(prioridade)

            if nodo_atual == "base":
                caminho = []
                while nodo_atual:
                    caminho.append(nodo_atual)
                    nodo_atual = predecessores.get(nodo_atual)
                return caminho[::-1], distancias["base"]

            for vizinho in grafo[nodo_atual]:
                aresta = grafo[nodo_atual][vizinho]
                distancia = aresta.get(f"distancia_{tipo_conexao}")
                if distancia is not None:
                    nova_distancia = distancia_atual + distancia
                    if nova_distancia < distancias[vizinho]:
                        distancias[vizinho] = nova_distancia
                        predecessores[vizinho] = nodo_atual
                        heappush(prioridade, (nova_distancia, vizinho))

        raise ValueError(f"Não há caminho para a base a partir de {origem}.")

    @staticmethod
    def distribuir_suprimentos_com_prioridade(caminho, veiculos, grafo, tipo_conexao, nodos_prioridade, suprimentos_total):
        """
        Distribui suprimentos ao longo de um caminho, considerando o tipo de conexão e priorizando nodos.

        :param caminho: Lista de nodos que representam o caminho a ser percorrido.
        :param veiculos: Lista de veículos disponíveis para transporte.
        :param grafo: Grafo representando as conexões entre os nodos.
        :param tipo_conexao: Tipo de conexão ("estrada", "rio", "aereo").
        :param nodos_prioridade: Lista de nodos de prioridade 3 para serem atendidos.
        :param suprimentos_total: Total de suprimentos disponíveis para distribuição.
        :return: Lista de atribuições realizadas durante a distribuição.
        """
        atribuicoes = []

        # Filtrar veículos pelo tipo de conexão
        veiculos_filtrados = [v for v in veiculos if v["terreno"] == tipo_conexao]

        if not veiculos_filtrados:
            return atribuicoes

        # Carregar veículos com suprimentos disponíveis
        for veiculo in veiculos_filtrados:
            if suprimentos_total <= 0:
                break
            carga = min(veiculo["capacidade"], suprimentos_total)
            veiculo["suprimentos"] = carga
            suprimentos_total -= carga

        i = 0
        while i < len(caminho) - 1:
            origem = caminho[i]
            destino = caminho[i + 1]

            # Atualizar autonomia ao passar por uma cidade ou base
            if origem.startswith("cidade") or origem == "base":
                for veiculo in veiculos_filtrados:
                    veiculo["autonomia"] = veiculo["autonomia_max"]

            # Obtém os atributos da aresta (origem -> destino)
            edge_data = grafo[origem][destino]
            distancia = edge_data.get(f"distancia_{tipo_conexao}")

            if distancia is None:
                break

            # Escolher o primeiro veículo disponível para esta etapa
            veiculo_escolhido = None
            for v in veiculos_filtrados:
                if v["autonomia"] >= distancia and v["suprimentos"] > 0:
                    veiculo_escolhido = v
                    break

            if not veiculo_escolhido:
                break

            # Atualizar autonomia do veículo
            veiculo_escolhido["autonomia"] -= distancia

            # Se o destino for um nodo de prioridade 3, atender sua necessidade
            if destino in nodos_prioridade:
                node_data = grafo.nodes[destino]
                necessidade = node_data.get("necessidade", 0)
                if necessidade > 0:
                    suprimento_entregue = min(veiculo_escolhido["suprimentos"], necessidade)
                    node_data["necessidade"] -= suprimento_entregue

                    if node_data["necessidade"] == 0:
                        node_data["prioridade"] = 0  # Atualizar prioridade para 0 somente se a necessidade for satisfeita

                    veiculo_escolhido["suprimentos"] -= suprimento_entregue

                    atribuicoes.append({
                        "veiculo_id": veiculo_escolhido["id"],
                        "origem": origem,
                        "destino": destino,
                        "distancia": distancia,
                        "suprimento_entregue": suprimento_entregue
                    })

            veiculo_escolhido["localizacao"] = destino

            # Verificar se o veículo precisa retornar à base
            if veiculo_escolhido["suprimentos"] == 0 or veiculo_escolhido["autonomia"] <= 0:
                # Retorna à base sem consumir autonomia
                try:
                    caminho_retorno, _ = SistemaDistribuicao.encontrar_caminho_para_base(grafo, destino, tipo_conexao)
                    veiculo_escolhido["localizacao"] = "base"
                    veiculo_escolhido["autonomia"] = veiculo_escolhido["autonomia_max"]
                    veiculo_escolhido["suprimentos"] = 0
                    break  # Para a distribuição ao retornar à base
                except ValueError as e:
                    print(f"Erro ao retornar à base: {e}")
                    break

            i += 1

        return atribuicoes





