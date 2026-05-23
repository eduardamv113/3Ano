# 📚 RESUMO DETALHADO - ANÁLISE DE DADOS E INTELIGÊNCIA (ADI)
**2021/22**

---

## 📋 ÍNDICE
1. [Sistemas de Aprendizagem](#sistemas-de-aprendizagem)
2. [Metodologias de Análise de Dados](#metodologias-de-análise-de-dados)
3. [Preparação de Dados](#preparação-de-dados)
4. [Avaliação de Modelos](#avaliação-de-modelos)
5. [Técnicas de Regressão](#técnicas-de-regressão)
6. [Métricas de Qualidade](#métricas-de-qualidade)
   - 6.1 [Métricas de Classificação](#métricas-de-classificação)
   - 6.2 [Métricas de Regressão](#métricas-de-regressão-crítico-para-o-exame)
7. [Árvores de Decisão](#árvores-de-decisão)
   - 7.1 [Algoritmos de Construção](#algoritmos-de-construção-de-árvores-de-decisão-crítico-para-o-exame)
   - 7.2 [Poda (Pruning)](#poda-pruning---conceito-crítico)
8. [Segmentação (Clustering)](#segmentação-clustering)
   - 8.1 [DBSCAN e Fórmulas de Distância](#fórmulas-de-distância-essencial-para-exercícios-práticos)
9. [Regras de Associação](#regras-de-associação-crítico---completamente-omisso-no-resumo-original)
10. [Redes Neuronais Artificiais](#redes-neuronais-artificiais)
    - 10.1 [Matemática do Treino](#matemática-do-treino-em-redes-neuronais-crítico-para-o-exame)
    - 10.2 [Treino Linear vs. Sigmoide](#treino-linear-vs-treino-sigmoide-backpropagation)
11. [Engenharia de Fluxos](#engenharia-de-fluxos-knime-e-keras)

---

## 1️⃣ SISTEMAS DE APRENDIZAGEM

### O que é um Sistema de Aprendizagem?
Um **sistema de aprendizagem** é um paradigma de computação em que a característica essencial se revela pela sua capacidade de **aprender de modo autónomo e independente**.

### 🎯 Três Tipos Principais de Aprendizagem

#### **A) Aprendizagem com Supervisão (Supervised Learning)**
- **Definição**: Paradigma em que os dados de treino contêm informação sobre os resultados pretendidos
- **Objetivo**: Estabelecer relação entre valores pretendidos e valores produzidos pelo sistema
- **Aplicações**:
  - **Classificação**: Resultados discretos (preto, branco, cinza, etc.)
  - **Regressão**: Resultados contínuos (temperatura, luz solar, preços, etc.)

#### **B) Aprendizagem sem Supervisão (Unsupervised Learning)**
- **Definição**: Paradigma em que NÃO são conhecidos os resultados sobre os casos, apenas os enunciados dos problemas
- **Objetivo**: Avaliar o funcionamento interno do sistema
- **Aplicações**:
  - **Segmentação/Clustering**: Organizar dados em grupos coerentes (ex: agrupar clientes que compram bebidas açucaradas)
  - **Associação**: Conhecer regras que associem comportamentos (ex: pessoas que compram bebidas açucaradas não compram bebidas alcoólicas)

#### **C) Aprendizagem por Reforço (Reinforcement Learning)**
- **Definição**: Paradigma que permite efetuar uma avaliação sobre se os resultados produzidos são bons ou maus
- **Características**:
  - Sem informação completa sobre resultados pretendidos
  - Usa técnicas de auto-alimentação de sinais
  - Conceitos de recompensa/penalização
  - NÃO é aprendizagem supervisionada (não há "professor")
  - NÃO é aprendizagem não supervisionada (existe informação sobre resultados)

#### **D) Aprendizagem Semi-Supervisionada (Semi-Supervised Learning) - NOVO**
- **Definição**: Paradigma que aproveita dados **parcialmente etiquetados** (alguns com solução, outros sem)
- **Objetivo**: Melhorar modelos e reduzir custo de etiquetar todos os dados
- **Contexto**: Entre supervisionado (100% labeled) e não-supervisionado (0% labeled)

**Técnicas Principais**:
- **Self-Training**: Treina com labeled, prevê unlabeled com alta confiança, adiciona pseudo-labels
- **Co-Training**: Dois modelos treinam independentemente e cooperam
- **Graph-Based**: Labels propagam entre dados similares
- **GANs**: Generator cria dados sintéticos para aumentar treino

**Aplicações**: Processamento áudio/vídeo, análise sentimentos, deteção fraude, reconhecimento imagens

---

## 2️⃣ METODOLOGIAS DE ANÁLISE DE DADOS

### O que é uma Metodologia de AD?
Uma **metodologia para análise de dados** descreve um conjunto de passos pelos quais deve passar o desenvolvimento de um projeto de **Machine Learning** para resolver problemas.

### 📊 CRISP-DM (Cross Industry Standard Process for Data Mining)

**O modelo de 6 etapas:**

1. **Estudo do Negócio**
   - Compreensão dos objetivos do projeto
   - Definição do problema de AD

2. **Estudo dos Dados**
   - Obter os dados
   - Identificar a qualidade dos dados

3. **Preparação dos Dados**
   - Seleção de atributos
   - Limpeza dos dados

4. **Modelação**
   - Experimentação com ferramentas de AD
   - Escolha de técnicas apropriadas

5. **Avaliação**
   - Comparação de resultados com objetivos do negócio
   - Validação do modelo

6. **Desenvolvimento**
   - Colocação do modelo em produção
   - Implementação e monitorização

### 🔄 SEMMA (Sample, Explore, Modify, Model and Assess)

**O modelo de 5 etapas:**

1. **Sample/Amostragem**
   - Extração de dados do universo do problema
   - Amostra pequena e significativa

2. **Explore/Exploração**
   - Exploração visual e/ou numérica das tendências
   - Utilização de técnicas estatísticas
   - Refinamento do processo de descoberta

3. **Modify/Modificação**
   - Realização de todas as modificações necessárias

4. **Model/Modelação**
   - Definição de técnicas de construção de modelos
   - Redes neuronais, árvores de decisão, regressão linear, etc.

5. **Assess/Avaliação**
   - Aferição do desempenho do modelo construído

### 📝 PMML (Predictive Model Markup Language)

- **Tecnologia**: Utiliza XML para descrever modelos de Data Mining
- **Vantagens**:
  - Aplicações utilizam diversas fontes de dados sem preocupações com diferenças
  - Utilização combinada e/ou cooperativa de modelos
  - Administração de modelos baseados em áreas de negócio

---

## 3️⃣ PREPARAÇÃO DE DADOS

### Importância
O principal objetivo da preparação de dados é **transformar os datasets** de forma a que a informação neles contida esteja **adequadamente exposta** à ferramenta de extração de conhecimento.

### 🚨 Problemas Comuns nos Dados Reais

Os dados recolhidos no "mundo real":
- **São incompletos**
  - Falta de valores em alguns atributos
  - Falta de atributos inteiros
- **Contêm "lixo"**
  - Valores impossíveis (ex: Salário: -1.000€)
  - Erros de entrada
- **Podem conter inconsistências**
  - Discrepâncias entre valores (ex: Idade = 35; Data nascimento = 31/maio/1969)

### 📋 Tarefas na Preparação de Dados

#### **1. Discretização/Enumeração**
- **Objetivo**: Redução de dados com aplicação a dados numéricos
- **Métodos**:
  - **Igual Largura**: Divide a gama de valores em N intervalos de igual largura
    - Fórmula: L = (B - A) / N, onde A e B são limites da gama
  - **Igual Altura**: Divide em N intervalos com aproximadamente a mesma quantidade de valores

#### **2. Limpeza de Dados**
**Como tratar ausência de dados?**
- Ignorar registos onde faltam dados
- Ignorar atributos onde faltam dados
- Preencher (manualmente) os dados em falta
- Preencher com o valor médio do atributo
- Preencher com o valor mais frequente do atributo

⚠️ **Cuidado**: Quanto mais valores "inventados", maior o desvio dos dados face à realidade!

#### **3. Integração dos Dados**
- Os dados podem ter proveniências diversas
- **Objetivo**: Compor informações numa coleção coerente e integrada
- **Requer**: "Conhecimento do negócio"

#### **4. Transformação de Dados**
- **Alisamento (Smoothing)**: Remover lixo/ruído (binning, regressão, clustering)
- **Agregação**: Resumo de dados iniciais (ex: vendas mensais em anuais)
- **Generalização**: Hierarquização de conceitos (distrito → cidade → rua)
- **Construção de Atributos**: Novos atributos a partir de outros (ex: preço líquido)
- **Uniformização**: Evitar que atributos com gama alargada sobressaiam
- **Deteção de Valores Atípicos**: Usando Box plots ou desvio padrão

#### **5. Redução de Dados**
- **Objetivo**: Obter representação reduzida mas com resultados analíticos semelhantes
- **Técnicas**:
  - Construção de cubos de dados
  - Redução de dimensões
  - Compressão de dados

---

## 4️⃣ AVALIAÇÃO DE MODELOS

### 🎯 Importância
Após a criação (treino) de um modelo, é **necessário avaliar seu desempenho** com dados NÃO apresentados durante o treino.

### 📊 Técnicas de Validação

#### **Hold-out Validation**
- Divide dados em conjunto de treino e teste
- Treina o modelo com um conjunto e avalia com outro
- **Vantagem**: Simples
- **Desvantagem**: Pode não utilizar bem todos os dados

#### **Cross Validation (K-fold)**
- Divide dados em K partes
- Treina K vezes, usando cada vez um subconjunto diferente como teste
- **Vantagem**: Melhor uso dos dados
- **Desvantagem**: Computacionalmente mais exigente

#### **Leave-One-Out Cross Validation (LOOCV, k=N)**
- Deixa apenas 1 amostra para teste
- Treina com N-1 amostras
- Repete N vezes
- **Vantagem**: Máxima utilização dos dados
- **Desvantagem**: Muito computacionalmente exigente

---

## 5️⃣ TÉCNICAS DE REGRESSÃO

### O que é Regressão?
A **regressão** é um procedimento estatístico que **determina a equação para a linha reta** que melhor se ajusta a um conjunto específico de dados.

### 📈 Tipos de Regressão

#### **A) Regressão Linear**
- Busca uma relação linear entre variáveis
- Equação: y = mx + b
- Adequada para relações lineares simples

#### **B) Regressão Linear Múltipla**
- Considera múltiplas variáveis independentes
- Equação: y = m₁x₁ + m₂x₂ + ... + mₙxₙ + b
- Mais flexível que regressão linear simples

#### **C) Regressão Logística**
- Usada quando resultado é categórico (0/1, Sim/Não)
- Produz probabilidades entre 0 e 1
- Adequada para problemas de classificação binária

---

## 6️⃣ MÉTRICAS DE QUALIDADE

### 🎯 Matrizes de Confusão

Para problemas de classificação, usamos:
- **Verdadeiros Positivos (TP)**: Previu corretamente como positivo
- **Falsos Positivos (FP)**: Previu positivo, mas era negativo
- **Verdadeiros Negativos (TN)**: Previu corretamente como negativo
- **Falsos Negativos (FN)**: Previu negativo, mas era positivo

### 📊 Métricas Derivadas

#### **Acurácia**
$$\text{Acurácia} = \frac{TP + TN}{TP + TN + FP + FN}$$
- Percentagem de previsões corretas

#### **Precisão**
$$\text{Precisão} = \frac{TP}{TP + FP}$$
- De todas as previsões positivas, quantas estavam corretas?

#### **Recall (Sensibilidade)**
$$\text{Recall} = \frac{TP}{TP + FN}$$
- De todas as instâncias positivas, quantas foram corretamente identificadas?

#### **F1-Score**
$$\text{F1} = 2 \times \frac{\text{Precisão} \times \text{Recall}}{\text{Precisão} + \text{Recall}}$$
- Média harmónica entre precisão e recall

#### **ROC Curve e AUC - NOVO**

**O Problema**: Métricas anteriores dependem de threshold fixo (0.5). E se mudarmos?

**Taxa de Verdadeiros Positivos (TPR)**:
$$TPR = \frac{TP}{TP + FN}$$

**Taxa de Falsos Positivos (FPR)**:
$$FPR = \frac{FP}{FP + TN}$$

**Curva ROC**: Plota FPR (eixo-X) vs TPR (eixo-Y) para todos os thresholds

**AUC (Area Under Curve)**:
$$AUC = \int_0^1 TPR(FPR) \, dFPR$$
- Intervalo: [0, 1]
- **AUC = 1.0**: Modelo perfeito
- **AUC = 0.5**: Modelo aleatório
- **AUC = 0.0**: Modelo completamente errado

**Vantagens**:
- ✅ Imune a dados desbalanceados (ao contrário de Acurácia)
- ✅ Mostra todos os thresholds e trade-offs
- ✅ Número único para comparar modelos

### 📈 Métricas de Regressão (CRÍTICO PARA O EXAME)

Para problemas de regressão (previsão de valores contínuos), o KNIME usa o nodo **Numeric Scorer** que calcula as seguintes métricas:

#### **MAE (Mean Absolute Error) - Erro Absoluto Médio**
$$MAE = \frac{1}{n}\sum_{j=1}^{n}|y_j - \hat{y}_j|$$
- Soma dos valores absolutos dos erros dividida pelo número de amostras
- **Interpretação**: Erro médio em unidades da variável (mesma escala dos dados)
- **Robustez**: Menos sensível a outliers que MSE
- **Uso**: Quando todos os erros têm importância similar

#### **MSE (Mean Squared Error) - Erro Quadrático Médio**
$$MSE = \frac{1}{n}\sum_{j=1}^{n}(y_j - \hat{y}_j)^2$$
- Soma dos erros ao quadrado dividida pelo número de amostras
- **Interpretação**: Penaliza **severamente os grandes erros** (porque cada erro é elevado ao quadrado)
- **Robustez**: Muito sensível a outliers
- **Uso**: Quando grandes erros são inaceitáveis

#### **RMSE (Root Mean Squared Error) - Raiz do Erro Quadrático Médio**
$$RMSE = \sqrt{\frac{1}{n}\sum_{j=1}^{n}(y_j - \hat{y}_j)^{2}}$$
- Raiz quadrada do MSE
- **Interpretação**: Retorna os erros à escala original dos dados (mesmas unidades que y)
- **Vantagem**: Mais interpretável que MSE porque está na mesma escala
- **Uso**: Métrica preferida quando queremos comunicar resultados a não-técnicos
- **Nota Importante - Penalização Geométrica**: MSE/RMSE têm comportamento não-linear. Ex: erro de 2 penaliza com 4, mas erro de 10 penaliza com 100! Por isto favorecem redução de erros grandes (outliers) vs MAE que trata todos os erros equitativamente

#### **R² (Coeficiente de Determinação)**
$$R^2 = 1 - \frac{\sum_{j=1}^{n}(y_j - \hat{y}_j)^2}{\sum_{j=1}^{n}(y_j - \bar{y})^2}$$
- Mede a **percentagem de variabilidade nos dados que é explicada pelo modelo**
- **Intervalo**: Entre 0 e 1
  - $R^2 = 1$: Modelo perfeito (ajusta-se 100% aos dados)
  - $R^2 = 0.5$: Modelo explica 50% da variabilidade
  - $R^2 = 0$: Modelo não melhor que usar a média
- **Interpretação**: "O modelo explica X% da variância dos dados"

#### **R² Ajustado (Adjusted R²)**
$$R^2_{adj} = 1 - \frac{(1-R^2)(n-1)}{n-p-1}$$
onde $n$ = número de amostras, $p$ = número de variáveis independentes
- **Correção**: Penaliza modelos que adicionam muitas variáveis desnecessárias
- **Uso**: Comparar modelos com diferentes números de features
- **Propriedade**: $R^2_{adj} \leq R^2$ sempre
- **Recomendação**: Usar $R^2_{adj}$ quando se comparam modelos com números diferentes de variáveis

---

## 7️⃣ ÁRVORES DE DECISÃO

### O que é uma Árvore de Decisão?
Uma **Árvore de Decisão** é um **grafo hierarquizado** em que:
- **Cada ramo** representa a seleção entre um conjunto de alternativas
- **Cada folha** representa uma decisão

### 🏗️ Modelos de Decisão

#### **Top-Down**
- Modelo construído a partir do conhecimento de especialistas
- O "todo" é dividido em "partes"

#### **Bottom-Up**
- Modelo construído pela identificação de relações entre atributos do dataset
- Modelo é induzido por "generalização" dos dados

### 🔄 Ciclo de Execução

1. Começar no nodo correspondente ao atributo "raiz"
2. Identificar o valor do atributo
3. Seguir pelo ramo correspondente ao valor
4. Alcançar o nodo relativo ao ramo percorrido
5. Voltar ao passo 2 até que o nodo seja uma "folha"
6. O nodo alcançado indica a decisão para o problema

### 📊 Tipos de Árvores de Decisão

#### **Árvores Contínuas**
- Atributo de decisão representa uma sequência, conjunto ou intervalos
- Folhas identificam intervalos ou conjuntos de valores

#### **Árvores Discretas**
- Atributo de decisão representa uma categoria ou classe
- Valores nas folhas são categorias ou classes

### 📐 Conceito de Entropia e Ganho de Informação

**Entropia** é uma medida da incerteza associada a um conjunto de objetos.
$$H(S) = -\sum_{i=1}^{c} p_i \log_2(p_i)$$
onde $p_i$ = proporção de exemplos da classe $i$ no conjunto $S$, $c$ = número de classes
- **Valor 0**: Todos os objetos são do mesmo valor (puro, máxima certeza)
- **Máximo**: Máxima incerteza/desordem (quando todas as classes têm proporção igual)
- **Exemplo**: Se temos 100 dados com 50 A e 50 B: $H = -0.5\log_2(0.5) - 0.5\log_2(0.5) = 1$ (máximo)

**Ganho de Informação**:
$$IG(S, A) = H(S) - \sum_{v \in Values(A)} \frac{|S_v|}{|S|} \times H(S_v)$$
- Mede a redução esperada na entropia quando se divide por um atributo $A$
- Determina qual atributo será selecionado para nodo
- O atributo com **maior ganho de informação** é a melhor escolha
- **Objetivo**: Minimizar a profundidade da árvore (menos splits)
- **⚠️ Defeito Grave**: Favorece atributos com muitos valores únicos (ex: ID_Cliente terá ganho máximo mas árvore é inútil!)
- **Solução**: C4.5 usa **Razão de Ganho (Gain Ratio)** que penaliza atributos com excesso de divisões

### 🔧 Algoritmos de Construção de Árvores de Decisão (CRÍTICO PARA O EXAME)

#### **ID3 (Iterative Dichotomiser 3)**
- **Criador**: J. Ross Quinlan (1986)
- **Critério**: Usa **Entropia e Ganho de Informação**
- **Limitações**:
  - Apenas para **atributos nominais/discretos** (não trata contínuos diretamente)
  - Tende a criar árvores muito grandes
  - Não lida bem com dados omissos (*missing values*)
  - Sem mecanismo de poda
- **Uso**: Histórico, pouco usado em produção

#### **C4.5 / J48**
- **Evolução**: Versão melhorada do ID3 por J. Ross Quinlan
- **Melhorias**:
  - Aceita **valores contínuos** (encontra thresholds automaticamente)
  - Lida com **dados omissos** (*missing values*) usando **pesos probabilísticos** proporcionais à frequência dos casos conhecidos
  - Realiza **poda de ramos** (pruning) para evitar overfitting
  - Usa **Razão de Ganho (Gain Ratio)** em vez de Ganho puro, penalizando atributos com muitos valores
- **Uso**: Muito popular em Data Mining (standard na indústria até 2000s)
- **Nota**: J48 é a implementação em Java do C4.5

#### **CART (Classification and Regression Trees)**
- **Criador**: Breiman et al. (1984)
- **Características Únicas**:
  - Realiza **divisões exclusivamente binárias** (cada nodo tem máximo 2 filhos)
  - Usa **Índice Gini** em vez de Entropia: $Gini(S) = 1 - \sum_{i=1}^{c} p_i^2$
  - Pode fazer tanto **Classificação como Regressão** (daí o nome)
  - Muito interpretável
- **Divisão Binária**: Para cada atributo, tenta encontrar o melhor ponto de divisão em dois subgrupos
- **Uso**: Padrão industrial, base para Random Forests e Gradient Boosting

#### **CHAID (Chi-squared Automatic Interaction Detection)**
- **Diferença Principal**: Realiza **divisões multi-nível** (cada nodo pode ter 3 ou mais filhos)
- **Critério**: Usa **teste de Chi-quadrado** para significância estatística
- **Vantagens**:
  - Divisões mais "naturais" com múltiplas categorias
  - Muito usado em Marketing e Segmentação de Clientes
  - Segue estrutura das variáveis categóricas
- **Interpretação**: Árvores mais compactas que CART ou C4.5

### 🔪 Poda (Pruning) - Conceito Crítico

**O que é Poda?**
Processo de **simplificação da árvore** após a sua construção, removendo ramos que não contribuem significativamente para a precisão.

**Por que Fazer Poda?**
- Evitar **overfitting** (sobreajustamento): A árvore cresce demais e memoriza dados de treino incluindo ruído
- Melhorar **generalização**: Árvores mais simples generalizam melhor em dados novos
- Reduzir **complexidade**: Árvores menores são mais rápidas e interpretáveis

**Tipos de Poda**:
1. **Poda por Redução de Erro (Error-Based Pruning)**:
   - Remove cada folha se o erro no conjunto de validação não aumentar
   - Abordagem gulosa: começa pelas folhas mais profundas

2. **Poda por Complexidade de Custo (Cost-Complexity Pruning)**:
   - Usa parâmetro $\alpha$ para balancear tamanho vs. precisão
   - Gera sequência de árvores do tamanho original até raiz
   - Usa validação cruzada para escolher $\alpha$ ótimo

### 💡 Aplicações das Árvores de Decisão
- **Classificação**: Categorizar novos dados em classes (maioria dos usos)
- **Regressão**: Prever valores contínuos (CART especificamente)
- **Explicabilidade**: Muito fácil explicar decisões ao negócio
- **Casos de Uso**: Aprovação de crédito, diagnóstico médico, segmentação

---

## 8️⃣ SEGMENTAÇÃO (CLUSTERING)

### O que é Segmentação?
A **Segmentação/Clustering** é um processo através do qual se **particiona um conjunto de dados** em segmentos/clusters de menor dimensão, agrupando conjuntos de dados similares.

### 🎯 Definição de um Cluster
Um **segmento/cluster** é uma coleção de valores/objetos que:
- **São similares entre si** dentro do mesmo segmento
- **São diferentes** dos valores/objetos de outros segmentos

### 📏 Medidas de Similaridade
- **Distância Euclidiana ou Manhattan**: Para atributos contínuos
- **Coeficiente de Jaccard**: Para atributos discretos/binários

### 💼 Utilização da Segmentação
- Suspeita da existência de agrupamentos "naturais"
- Representam grupos de clientes, produtos ou bens que compartilham informação
- Muitos padrões diferentes nos dados, dificultando identificar um padrão específico

### 📊 Tipos de Dados para Análise

#### **1. Atributos Contínuos**
- **Tratamento**: Normalizar dados para evitar dependência de unidades de medida
- **Similaridade**: Usar medidas de distância

#### **2. Atributos Binários**
- **Simétricos**: Significado de 0 = Significado de 1 (coeficiente simples)
- **Assimétricos**: Significado de 0 ≠ Significado de 1 (coeficiente Jaccard)
- **Similaridade invariante** vs **não-invariante**

#### **3. Atributos Nominais**
- Generalização dos atributos binários (mais de 2 valores)
- **Método 1**: Usar variáveis binárias
- **Método 2**: Criar uma variável binária para cada valor nominal

#### **4. Atributos Ordinais**
- A ordem é relevante
- Tratados como atributos contínuos
- Ordenação define uma classificação

#### **5. Atributos Mistos**
- Dataset contém diversos tipos de atributos
- Usar função pesada para ponderar efeitos de cada atributo

### 🔧 Principais Métodos de Segmentação

#### **A) Algoritmos de Particionamento**
Criam várias partições com critério de avaliação.

**Método k-means**:
- Encontra K centros de clusters
- Aloca cada ponto ao centro mais próximo
- Itera até convergência
- **Vantagem**: Simples e rápido
- **Desvantagem**: Requer escolha prévia de K

**Método k-medoids**:
- Similar a k-means mas usa medoides (pontos reais) em vez de centroides
- Mais robusto a outliers

#### **B) Algoritmos de Hierarquização**
Decompõem hierarquicamente o conjunto de dados.

**AGNES (Agglomerative Nesting)**:
- Abordagem bottom-up
- Começa com cada ponto como cluster separado
- Sucessivamente junta clusters mais próximos
- Cria dendrograma

**DIANA (Divisive Analysis)**:
- Abordagem top-down
- Começa com todos os pontos num cluster
- Sucessivamente divide clusters

#### **C) Algoritmos Baseados em Densidade**

**DBSCAN (Density-Based Spatial Clustering of Applications with Noise)**
- **Abordagem**: Algoritmo revolucionário que identifica clusters baseado em **densidade de pontos**
- **Funcionamento**:
  1. Define dois parâmetros:
     - $\epsilon$ (Eps): Raio de vizinhança (distância máxima para considerar um ponto vizinho)
     - $MinPts$: Número mínimo de pontos dentro do raio $\epsilon$ para formar um cluster
  2. Para cada ponto:
     - Se tem $\geq MinPts$ vizinhos dentro de $\epsilon$: Ponto **central**
     - Se está dentro de $\epsilon$ de um ponto central: Ponto **fronteira**
     - Caso contrário: **Ruído/Outlier**
  3. **Regra de Conectividade (Formal)**: Um ponto Fronteira pertence ao cluster do ponto Central que o alcançou primeiro. Se não for Central nem Fronteira, é classificado como **Ruído**.
  4. Grupos de pontos centrais conectados formam clusters

- **Vantagens**:
  - ✅ Descobre clusters de **formas geométricas irregulares** (não apenas esféricas como k-means)
  - ✅ Identifica **ruído/outliers** automaticamente (não os força em clusters)
  - ✅ **Não requer escolha prévia de K**
  - ✅ Um único varrimento dos dados (*single pass*)

- **Desvantagens**:
  - ⚠️ Sensível à escolha de $\epsilon$ e $MinPts$
  - ⚠️ Desempenho varia com dimensionalidade dos dados (em altas dimensões fica impreciso)

- **Aplicações**:
  - Deteção de anomalias
  - Clustering geoespacial
  - Análise de padrões em imagens

### 📏 Fórmulas de Distância (Essencial para Exercícios Práticos)

#### **Distância Euclidiana**
$$d_{euclidiana}(p, q) = \sqrt{(x_p - x_q)^2 + (y_p - y_q)^2 + \ldots + (z_p - z_q)^2}$$
- **Interpretação**: Linha reta (diagonal) entre dois pontos
- **Geometria**: Em 2D é a hipotenusa do triângulo retângulo
- **Uso**: Atributos contínuos, espaços Euclidianos normais
- **Exemplo em 2D**: Pontos $(3, 4)$ e $(0, 0)$ → $d = \sqrt{3^2 + 4^2} = 5$
- **Nota**: Afetada por escalas diferentes das variáveis (deve-se normalizar)

#### **Distância de Manhattan (ou Distância de Bloco)**
$$d_{manhattan}(p, q) = |x_p - x_q| + |y_p - y_q| + \ldots + |z_p - z_q|$$
- **Interpretação**: Trajeto em grelha (como ruas de uma cidade em blocos)
- **Geometria**: Soma das distâncias horizontais e verticais
- **Uso**: Dados em grelha, sistemas de coordenadas urbanas
- **Exemplo em 2D**: Pontos $(3, 4)$ e $(0, 0)$ → $d = |3 - 0| + |4 - 0| = 7$
- **Vantagem**: Menos afetada por outliers que Euclidiana
- **Comparação**: Manhattan sempre $\geq$ Euclidiana

#### **Distância de Chebyshev**
$$d_{chebyshev}(p, q) = \max(|x_p - x_q|, |y_p - y_q|, \ldots, |z_p - z_q|)$$
- **Interpretação**: Maior diferença em qualquer dimensão
- **Uso**: Quando importa apenas a pior coordenada

#### **Coeficiente de Jaccard (para Atributos Binários/Discretos)**
$$Jaccard(A, B) = \frac{|A \cap B|}{|A \cup B|} = \frac{n_{11}}{n_{01} + n_{10} + n_{11}}$$
onde:
- $n_{11}$ = Ambos têm valor 1
- $n_{01}$ = A tem 0, B tem 1
- $n_{10}$ = A tem 1, B tem 0
- Intervalo: [0, 1]
  - 1 = Idênticos
  - 0 = Completamente diferentes

### ✅ Vantagens e Desvantagens

| Método | Vantagens | Desvantagens |
|--------|-----------|-------------|
| k-means | Simples, rápido, escalável | Requer K pré-determinado, sensível a inicialização |
| k-medoids | Robusto a outliers, interpretável | Mais lento que k-means |
| AGNES | Não requer K, dendrograma informativo | Computacionalmente exigente |
| DIANA | Explica progressivamente | Menos usado, complexo |
| DBSCAN | Detecta forma irregular, encontra outliers | Sensível a parâmetros $\epsilon$ e $MinPts$ |

---

## 9️⃣ REDES NEURONAIS ARTIFICIAIS (RNA)

### O que é uma Rede Neuronal Artificial?
Uma **Rede Neuronal Artificial (RNA)** é um **sistema computacional de base conexionista** para resolução de problemas, concebida com base num modelo simplificado do sistema nervoso central dos seres humanos.

**Definição Técnica**: Uma RNA é uma estrutura interligada de unidades computacionais (neurónios) com capacidade de aprendizagem.

### 🎓 Motivação Histórica: O Problema do XOR - NOVO

#### **Por que Perceptron Simples Falha (e por que precisamos de Deep Learning)**

**O Desafio**: O Perceptron simples com função linear consegue resolver problemas **linearmente separáveis**, mas **falha completamente com XOR**.

**Truth Table do XOR**:

| Input 1 | Input 2 | XOR |
|---------|---------|-----|
| 0       | 0       | 0   |
| 0       | 1       | 1   |
| 1       | 0       | 1   |
| 1       | 1       | 0   |

**O Problema Geometricamente**:
- Pontos com output 0: (0,0) e (1,1)
- Pontos com output 1: (0,1) e (1,0)
- **Nenhuma reta consegue separar estes pontos!** (problema não-linearmente separável)

**Formalização Matemática**:
Com função linear $f(x) = w_1 \cdot p + w_2 \cdot q + b$, é **impossível** atingir:
- Output ≥ 0.5 para (0,1) e (1,0)
- Output < 0.5 para (0,0) e (1,1)

#### **Solução: Multi-Layer Perceptron com Não-Linearidade**

Com **múltiplas camadas + função sigmoide/ReLU**:
1. Primeira camada transforma espaço 2D em espaço maior (não-linearmente)
2. Segunda camada faz separação no novo espaço
3. Resultado: ✅ Consegue resolver XOR perfeitamente!

**Impacto Histórico**:
- Mostrou limitação fundamental do Perceptron (anos 1970-80)
- Motivou **backpropagation** (treino multicamadas)
- Fundação para **Deep Learning moderno**

---

### 🧠 Conceitos Fundamentais

#### **1. Neurónio**
- **Unidade computacional** que compõe a RNA
- **Identificado** pela sua posição na rede
- **Caracterizado** pelo valor do estado

#### **2. Axónio**
- Via de comunicação entre neurónios
- Pode ligar qualquer neurónio, incluindo o próprio
- Ligações podem variar ao longo do tempo
- **Informação circula em um só sentido**

#### **3. Sinapses**
- Ponto de ligação entre axónios e neurónios
- **Valor da sinapse** determina o peso (importância) do sinal
- Pode ser:
  - Excitativo: Potencia o sinal
  - Inibidor: Reduz o sinal
  - Nulo: Sem efeito
- **Variação no tempo** = Aprendizagem da RNA

#### **4. Ativação**
- Representado por um único valor
- Varia com o tempo
- Gama de valores varia com o modelo adotado

#### **5. Transferência**
- Valor de transferência determina o valor na saída do neurónio
- Calculado como função do valor de ativação
- Função de ativação comum: Sigmoid, ReLU, Tanh

### 🏗️ Organização dos Neurónios

As redes podem ser organizadas em:
- **Camada de entrada**: Recebe os dados
- **Camadas ocultas**: Processam informação
- **Camada de saída**: Produz resultado

### 🎓 Aprendizagem em RNA

A aprendizagem em redes neuronais ocorre através de:
- Ajuste de pesos das sinapses
- Algoritmo de retro-propagação (backpropagation)
- Descida de gradiente para otimizar pesos

### 🎯 Como Funcionam?

**Como as RNAs lidam com dados**:
- ✅ Identificam padrões nos dados
- ✅ Retêm características dos dados

**Como resolvem problemas**:
- ✅ Criam regras de comportamento a partir dos dados
- NÃO recuperam soluções presentes apenas nos dados
- NÃO hierarquizam dados diretamente
- NÃO agrupam dados em segmentos (embora possam usar clustering)

### 💪 Vantagens das RNAs

| Vantagem | Descrição |
|----------|-----------|
| **Adaptabilidade** | Aprendem e adaptam-se aos dados |
| **Reconhecimento de Padrões** | Identificam padrões complexos não-lineares |
| **Paralelização do Processamento** | Podem processar informação em paralelo |
| **Não Linearidade** | Conseguem modelar relações não-lineares |
| **Aprendizagem** | Aprendem diretamente dos dados |

### 📊 Tipos de Redes Neuronais

#### **1. Feed-Forward (Redes Diretas)**
- Informação flui apenas para a frente
- Sem loops/cycles
- Mais comum e simples

#### **2. Convolutional Neural Networks (CNN)**
- Inspiradas em processamento visual
- **Eficácia Declarada (Literatura Oficial)**:
  - Reconhecimento de imagens: **100%** ✅
  - Reconhecimento ótico de caracteres (OCR): **100%** ✅
  - Deteção facial: **100%** ✅
  - Imagiologia Médica: **75%**
  - Segmentação de imagens: **62,5%**
  - Sistemas de recomendação: **62,5%**

#### **3. Recurrent Neural Networks (RNN) - EXPANDIDO**
- **Inovação**: Loops - a saída volta para dentro como entrada!
- **Permite**: Processar sequências (texto, séries, vídeo) com memória de contexto

**Equação Básica**:
$$h_t = f(W_h \times h_{t-1} + W_x \times x_t + b)$$
onde $x_t$ = input, $h_t$ = hidden state (memória), $h_{t-1}$ = estado anterior

**Características**:
  - ✅ Captam noção de tempo
  - ✅ Capacidade de memorização
  - ✅ Preservação de memória recente
  - ⚠️ **Problema Principal**: Vanishing Gradient em sequências longas

**Problema Crítico - Vanishing Gradient**:
- Em backpropagation, gradiente é multiplicado por cada timestep
- Se cada fator < 1 → produto torna-se praticamente zero após 50+ passos
- **Resultado**: RNN não consegue aprender dependências de longo prazo
- **Exemplo**: Frase com 100 palavras - RNN esquece contexto das primeiras 50

**Eficácia Declarada (Literatura Oficial)**:
  - Previsão de séries temporais: **100%** ✅
  - Processamento de Linguagem Natural (NLP): **90,9%**
  - Análise de vídeo: **81,8%**
  - Reconhecimento de fala: **72,7%**
  - Tradução automática: **63,6%**

#### **4. LSTM (Long Short-Term Memory) - EXPANDIDO**
- **Inovação**: Separa **cell state** (memória) de **hidden state** (output)
- **Estrutura**: 3 Gates (Forget, Input, Output)

**Como Funciona**:
1. **Forget Gate**: Decide que informação esquecer
2. **Input Gate**: Decide que informação nova adicionar
3. **Cell State Update** (CRÍTICO): Usa adição (não multiplicação) → evita vanishing gradient
4. **Output Gate**: Decide quanto do cell state sai

**Vantagem Principal**: 
- ✅ Memória de longo prazo → consegue lembrar de 100+ timesteps
- ✅ Soluciona vanishing gradient
- ✅ SOTA para NLP durante 20 anos

#### **5. GRU (Gated Recurrent Unit) - EXPANDIDO**
- **Inovação**: Simplificação de LSTM (2 gates em vez de 3)
- **Vantagem vs LSTM**: Menos parâmetros = treino mais rápido
- **Performance**: Similar em maioria dos casos, ligeiramente inferior em sequências muito longas
- **Recomendação**: Usar quando dados são limitados ou treino deve ser rápido

#### **6. Transformers - Arquitetura Moderna (ESTADO-DA-ARTE)**
- Arquitetura revolucionária baseada em **Attention** (não recorrência)
- **Inovação**: Processa sequências **em paralelo** (RNN processa sequencialmente)

**Vantagens Críticas**:
  - ✅ Paralelização completa → Treino 10-100× mais rápido
  - ✅ Cada elemento "vê" todos os outros → Contextualização global
  - ✅ Sem recorrência → Sem vanishing gradient
  - ✅ Escalável para sequências muito longas (1000+ elementos)

**Desvantagens**:
  - ⚠️ Mais complexo de implementar
  - ⚠️ Mais memória (matriz atenção N×N)
  - ⚠️ Requer mais dados para treinar

**Conceito-Chave: Attention**:
- Cada token "atende" (pesa) todos os outros tokens
- Scores de atenção determinam relevância
- Resultado: contexto global sem loops

**Caraterísticas Definidoras**:
- ✅ **Paralelização** - Processa sequência inteira em paralelo (vs RNN sequencial)
- ✅ **Mecanismo de Atenção** - Substitui recursividade temporal
- ✅ **Contextualização Temporal Global** - Cada posição "vê" todas as outras
- ✅ **Arquitetura Sequence-to-Sequence** - Encoder-decoder ou decoder-only

**Domínio Atual (2026)**:
- 🏆 **GPT** (OpenAI), **Claude** (Anthropic), **Gemini** (Google): Transformers decoder-only
- 🏆 **BERT** (Google): Transformers encoder-only
- 🏆 **Vision Transformers (ViT)**: Transformers para imagens
- **Consenso**: Transformers são o standard industrial para IA em 2026

**Aplicações Dominantes**:
  - Chatbots e assistentes (Chat GPT, Claude)
  - Tradução automática, sumarização, Q&A
  - Análise de sentimentos, geração de texto
  - Reconhecimento de imagens (ViT)
  - Modelos multimodais (texto + imagem)

#### **7. Deconvolutional Networks**
- Reverso das CNNs
- Usadas para tarefas de síntese e upsampling

#### **8. Generative Adversarial Networks (GANs)**
- Duas redes em competição: Generator e Discriminator
- Usado para geração de dados sintéticos

---

## 🧮 MATEMÁTICA DO TREINO EM REDES NEURONAIS (CRÍTICO PARA O EXAME)

### 📡 Estrutura de Processamento do Neurónio

Cada neurónio realiza dois passos fundamentais:

**1. Função de Integração (Soma Pesada)**
$$A = \sum_{i=1}^{n} w_i \times e_i + bias$$
onde:
- $w_i$ = Peso da sinapse $i$ (força da ligação)
- $e_i$ = Entrada (sinal) do neurónio $i$
- $bias$ = Termo de viés (constante adicionada)
- $A$ = Ativação (valor resultante antes da transferência)

**2. Função de Ativação/Transferência**
$$o = f_T(A)$$
onde $f_T$ é uma função não-linear, como:
- **Função Sigmoide**: $f_T(A) = \frac{1}{1 + e^{-A}}$ (output entre 0 e 1)
- **Função Tanh**: $f_T(A) = \frac{e^A - e^{-A}}{e^A + e^{-A}}$ (output entre -1 e 1)
- **Função ReLU**: $f_T(A) = \max(0, A)$ (output ≥ 0, muito usada em Deep Learning)
- **Função Linear**: $f_T(A) = A$ (usada no treino linear)

**Fluxo Completo do Neurónio**:
```
Inputs (e₁, e₂, ..., eₙ) → Soma Pesada (A = Σ wᵢ×eᵢ + bias) → Função de Ativação (o = fₜ(A)) → Output (o)
```

### 🎓 Regras de Aprendizagem Formais

#### **1. Regra de Hebb (Aprendizagem Não-Supervisionada)**
$$\Delta w_i = \eta \times e_i \times o$$
onde:
- $\Delta w_i$ = Ajuste do peso
- $\eta$ = Taxa de aprendizagem
- $e_i$ = Input do neurónio
- $o$ = Output do neurónio

**Princípio**: "Neurónios que disparam juntos, reforçam a sua ligação"
**Mecanismo**: Se entrada e saída estão ativas (1) → aumenta peso; se apenas uma está ativa → diminui peso
**Limitação**: Apenas para aprendizagem não-supervisionada; sem informação de erro

#### **2. Regra do Perceptron (Aprendizagem Supervisionada - Erro Discreto)**
$$\Delta w_i = \eta \times (y - o) \times e_i$$
onde:
- $y$ = Valor esperado (target)
- $o$ = Output real do neurónio
- $(y - o)$ = Erro discreto {0, +1, -1}

**Funcionamento**:
- Se previsão correta: $(y - o) = 0$ → sem ajuste
- Se previsão incorreta: Ajusta proporcionalmente ao erro e à entrada

**Limitação**: Apenas para problemas linearmente separáveis

#### **3. Regra Delta / Widrow-Hoff (Aprendizagem Supervisionada - Erro Contínuo)**
$$\Delta w_i = \eta \times (y - o) \times e_i$$
onde $(y - o)$ agora é um **valor contínuo** (não discreto como no Perceptron)

**Propriedade**: Minimiza o Erro Quadrático Médio (MSE)
**Vantagem**: Converge mesmo para dados não-linearmente separáveis
**Variante**: Conhecida como **Descida de Gradiente**:
$$\Delta w_i = -\eta \times \frac{\partial E}{\partial w_i}$$
onde $E$ = Erro total da rede

### 🔄 Treino Linear vs. Treino Sigmoide (Backpropagation)

#### **Treino Linear**

**Função de Transferência**:
$$f_T(A) = A \text{ (identidade)}$$

**Características**:
- Output = Ativação (sem compressão)
- Pode produzir qualquer valor real
- Simples mas limitado: **redes lineares só conseguem modelar relações lineares**

**Atualização de Pesos (Regra Delta Simples)**:
$$\Delta w_i = \eta \times (y - o) \times e_i$$
onde:
- $o = A$ (porque $f_T = identidade$)
- Nenhuma derivada necessária

**Limitação**: Se o problema requer não-linearidade (ex: XOR), falha completamente

#### **Treino Sigmoide (Backpropagation)**

**Função de Transferência**:
$$f_T(A) = \frac{1}{1 + e^{-A}}$$
onde:
- Output está sempre entre 0 e 1 (comprimido)
- Função **não-linear e diferenciável**

**Derivada da Sigmoide** (crítica para backpropagation):
$$\frac{df_T}{dA} = f_T(A) \times (1 - f_T(A)) = o \times (1 - o)$$

**Algoritmo de Backpropagation** (retro-propagação do erro):

1. **Forward Pass** (propagar inputsaté output):
   - Calcula $A = \sum w_i \times e_i + bias$
   - Calcula $o = f_T(A) = \frac{1}{1 + e^{-A}}$

2. **Calcular Erro na Saída**:
   $$\mathcal{E} = y - o$$

3. **Backpropagation** (calcular erro em camadas anteriores):
   - **Camada de Saída** - Erro retro-propagado (delta):
   $$\delta_{saida} = \mathcal{E} \times \frac{df_T}{dA} = \mathcal{E} \times o \times (1 - o)$$
   
   - **Camadas Ocultas** - Erro estimado (sem target direto):
   $$\mathcal{E}_{oculto} = \sum (\delta_{camada\_seguinte} \times w_{ligação})$$
   
   Depois aplica-se a derivada local:
   $$\delta_{oculto} = \mathcal{E}_{oculto} \times o_{oculto} \times (1 - o_{oculto})$$
   
   Este é o processo "de trás para frente" - o erro soma-se pesadamente de todas as camadas seguintes, é ajustado pela derivada local, e propaga-se para neurónios anteriores

4. **Atualizar Pesos** (descida de gradiente):
   $$\Delta w_i = \eta \times \delta \times e_i = \eta \times \mathcal{E} \times o \times (1 - o) \times e_i$$

**Por que Backpropagation é Revolucionário**:
- ✅ Consegue treinar redes **multicamadas** (Deep Learning)
- ✅ Consegue modelar relações **não-lineares complexas**
- ✅ Propaga o erro através de todas as camadas eficientemente
- ✅ Multiplicador $(o \times (1-o))$ controla a intensidade do ajuste

**Multiplier Factor Crítico**:
O fator $(o \times (1-o))$ controla a intensidade do ajuste:

| Valor de $o$ | $(1-o)$ | Produto | Intensidade |
|--------------|---------|---------|-------------|
| 0 (muito errado) | 1 | ~0 | Ajuste MÍNIMO |
| 0.25 | 0.75 | ~0.19 | Ajuste médio |
| **0.5** (incerto) | **0.5** | **~0.25** | Ajuste **MÁXIMO** ✅ |
| 0.75 | 0.25 | ~0.19 | Ajuste médio |
| 1 (muito certo) | 0 | ~0 | Ajuste MÍNIMO |

**Intuição**: Quando rede está certa (output 0 ou 1) → ajuste pequeno; quando incerta (~0.5) → ajuste máximo.

#### **⚡ Vanishing/Exploding Gradient (CRÍTICO PARA DEEP LEARNING)**

**Em Redes Profundas**, o gradiente viaja de trás para frente através de **todas as camadas**:

Para camada $i$: Multiplica derivada de CADA camada = $\prod_{j=i}^{L-1} o^{(j)} \times (1 - o^{(j)})$

**VANISHING GRADIENT (Desaparecimento)**:

Se cada fator $(o \times (1-o)) < 1$:

**Exemplo Numérico Real**:
```
Camada 1: Gradiente = 1.0
Camada 2: × 0.25 = 0.25
Camada 3: × 0.25 = 0.0625
Camada 4: × 0.25 = 0.0156
Camada 5: × 0.25 = 0.0039
...
Camada 50: × 0.25 ≈ 1e-28 (UM TRILIÃO DE VEZES MAIS PEQUENO!)
```

**Efeito**: Pesos em camadas **antigas (perto do input) quase não atualizam** → Treino não converge!

**Contexto Histórico**:
- Este foi o **maior desafio do Deep Learning** nos anos 1980-2000
- Impossível treinar redes com mais de ~5-7 camadas
- Razão pela qual Deep Learning "parou" até 2006
- Quando Geoffrey Hinton descobriu pré-treino (RBM) → **Renascimento do Deep Learning**

**EXPLODING GRADIENT (Explosão)**:

Inversamente, se derivada > 1:
- Gradiente cresce exponencialmente: $(2)^{50}$ = $10^{15}$ (ENORME!)
- Pesos sofrem atualizações **gigantescas** → divergem para ∞ ou NaN
- **Treino explode** (loss aumenta)

#### **💡 Soluções Implementadas**

| Solução | Mecanismo | Efeito |
|---------|-----------|--------|
| **ReLU** | $f_T(A) = \max(0, A)$ tem derivada = 1 | Evita multiplicação < 1 |
| **Batch Normalization** | Normaliza ativações entre camadas | Mantém valores em escala |
| **Gradient Clipping** | Limita $\|\|grad\|\|$ a threshold | Evita explosão |
| **LSTM** | Gates controlam multiplicação | Caminho "shortcut" |
| **Skip Connections** | ResNet: $h = x + f(x)$ | Gradiente passa direto |

**LSTM Solução Específica**:

Cell state update: $C_t = f_t \odot C_{t-1} + i_t \odot \tilde{C}_t$

Quando $f_t \approx 1$ (forget gate "aceso"), cell state passa **quase intacto**:
$$C_t \approx C_{t-1} + \Delta C$$

Isto = **adição em vez de multiplicação** → **gradiente propaga sem desaparecer**!

---

**Comparação Linear vs. Sigmoide**:
| Aspeto | Treino Linear | Treino Sigmoide |
|--------|---------------|------------------|
| Função de Ativação | $f_T(A) = A$ | $f_T(A) = \frac{1}{1+e^{-A}}$ |
| Output | Qualquer valor real | Entre 0 e 1 |
| Capacidade | Relações lineares | Relações não-lineares |
| Diferenciação | Trivial (=1) | $o(1-o)$ |
| Número de Camadas | Uma camada | Múltiplas camadas |
| Algoritmo Treino | Delta simples | Backpropagation |
| Aplicações | Regressão linear simples | Classificação, Redes profundas |

---

## 📋 REGRAS DE ASSOCIAÇÃO (CRÍTICO - Completamente Omisso no Resumo Original)

### O que são Regras de Associação?
**Regras de Associação** são regras do tipo IF-THEN que descrevem padrões de co-ocorrência nos dados.
**Exemplo**: "Se um cliente compra Pão E Leite, então tem 80% de chance de comprar Manteiga"
**Aplicações**: Recomendação de produtos, análise de cestros de compras (market basket analysis)

### 🔍 Métricas Fundamentais

#### **Suporte (Support)**
$$Support(A \rightarrow C) = \frac{|transações\ com\ A\ e\ C|}{|total\ de\ transações|}$$
- **Significado**: Frequência relativa com que um conjunto de itens aparece no dataset
- **Intervalo**: Entre 0 e 1 (ou percentagem)
- **Interpretação**: "Em quantas transações tanto A como C aparecem?"
- **Exemplo**: Support({Pão, Leite}) = 0.15 → "15% de todas as transações contêm Pão E Leite"
- **Regra Prática**: Suportes baixos (<5%) indicam relações raras (podem ser ignoradas em grandes datasets)

#### **Confiança (Confidence)**
$$Confidence(A \rightarrow C) = \frac{|transações\ com\ A\ e\ C|}{|transações\ com\ A|}$$
- **Significado**: A certeza condicional de que o consequente C é comprado DADO que o antecedente A foi comprado
- **Intervalo**: Entre 0 e 1 (ou percentagem)
- **Interpretação**: "De todos os clientes que compraram A, quantos também compraram C?"
- **Exemplo**: Confidence(Pão → Manteiga) = 0.80 → "De todos os clientes que compraram Pão, 80% também compraram Manteiga"
- **Uso**: Avaliar a força da regra (maior = melhor)

#### **Lift (Elevação)**
$$Lift(A \rightarrow C) = \frac{Confidence(A \rightarrow C)}{Support(C)} = \frac{P(C|A)}{P(C)}$$
- **Significado**: Mede a **correlação/associação** entre A e C
- **Intervalo**: Valores positivos
  - $Lift > 1$: Associação **positiva** (A e C aparecem mais juntos do que por acaso)
  - $Lift \approx 1$: Independência (A e C não são correlacionados)
  - $Lift < 1$: Associação **negativa** (A e C aparecem menos juntos do que por acaso)
- **Interpretação**: "Quantas vezes mais provável é comprar C se comprou A (vs. a probabilidade geral de C)"
- **Exemplo**: Lift(Pão → Vinho) = 2.5 → "Se comprou Pão, a chance de comprar Vinho é 2.5× maior"
- **Uso**: Excelente para descobrir relações **não-óbvias e raras**
- **Vantagem sobre Confiança**: Não afetado pela frequência do consequente

#### **Leverage (Potência)**
$$Leverage(A \rightarrow C) = P(A \cap C) - P(A) \times P(C) = Support(A \rightarrow C) - Support(A) \times Support(C)$$
- **Significado**: Proporção de exemplos adicionais que estão sob o âmbito de ambos antecedente e consequente
- **Intervalo**: Entre -1 e +1
  - Leverage > 0: Dependência positiva
  - Leverage = 0: Independência
  - Leverage < 0: Dependência negativa
- **Interpretação**: "Diferença entre observado e esperado por acaso"
- **Exemplo**: Leverage = 0.05 → "5% mais transações contêm A e C do que seria esperado se fossem independentes"
- **Vantagem**: Valoriza relações com **forte suporte** (não apenas confiança alta)

#### **Conviction (Convicção) - NOVO**
- **Significado**: Expectativa de quantas vezes o antecedente ocorre SEM o consequente
- **Intervalo**: Valores positivos
  - Conviction > 1: Relação forte (A raramente ocorre sem C)
  - Conviction = 1: Independência
- **Uso**: Avaliar força da implicação (A → C é obrigatório?)

---

### 🔧 Algoritmos de Descoberta

#### **Algoritmo Apriori**
- **Principio**: "Se um conjunto de itens é frequente, então todos os seus subconjuntos também são frequentes"
- **Funcionamento** (simplificado):
  1. Encontra todos os itens individuais frequentes (support > minsupp)
  2. Combina-os em pares e verifica frequência
  3. Combina pares frequentes em triplos, etc.
  4. Para cada combinação frequente, gera regras IF-THEN
- **Vantagem**: Simples, garantido encontra todas as regras
- **Desvantagem**: Muito lento em datasets grandes (exponencial no número de itens)

#### **FP-Growth (Frequent Pattern Growth)**
- **Melhoria sobre Apriori**: Usa estrutura de dados especializada (FP-tree)
- **Vantagem**: Muito mais rápido (não precisa de gerar todos os candidatos)
- **Ideal para**: Grandes datasets e análise rápida

---

## 🛠️ ENGENHARIA DE FLUXOS (KNIME e Keras)

### 📊 Fluxo Padrão Supervisionado no KNIME

Este é o fluxo mais comum em exames e projetos práticos:

```
CSV Reader
    ↓
Data Exploration (visualizar, estatísticas)
    ↓
Partitioning (dividir em Treino 70% / Teste 30%)
    ├─→ Treino
    │   ↓
    │   [Learner] (ex: Decision Tree Learner, Neural Network Learner)
    │   ↓
    │   Modelo Treinado
    │
    └─→ Teste
        ↓
        [Predictor]
        ↓
        Previsões
        ↓
        [Scorer] (para classificação) ou [Numeric Scorer] (para regressão)
        ↓
        Métricas de Desempenho (Acurácia, F1, MAE, RMSE, R²)
```

**Nodos Essenciais (Nomenclatura Oficial KNIME)**:
- **CSV Reader**: Lê dados de ficheiro
- **Partitioning**: Estratifica em Treino/Teste (escolhe seeds aleatórias)
- **Decision Tree Learner / Neural Network Learner / Linear Regression Learner**: Nodos de aprendizagem
- **Predictor**: Aplica o modelo aos dados de teste
- **Scorer (JavaScript)**: Gera Matriz de Confusão (classificação)
- **Numeric Scorer**: Calcula métricas de regressão (MAE, MSE, RMSE, R²)

### 🧠 Fluxo de Redes Neuronais no KNIME

```
CSV Reader
    ↓
Normalizer (CRÍTICO: escalar features para [0,1] ou [-1,1])
    ↓
Partitioning (Treino/Teste)
    ├─→ [RProp Multi-Layer Perceptron Learner] ← Nome exato KNIME
    │   Configurações:
    │   - Hidden Layer Sizes (ex: 10,5,5)
    │   - Activation Function (Sigmoide, Tanh, ReLU)
    │   - Epochs (iterações)
    │   - Learning Rate (taxa de aprendizagem)
    │   ↓
    │   Modelo Treinado
    │
    ├─→ [Multi-Layer Perceptron Predictor] ← Nome exato KNIME
    │   ↓
    └─→ [Scorer (JavaScript)] para classificação
        [Numeric Scorer] para regressão
```

**Nomenclatura Oficial KNIME**:
- Nodo de Treino: **`RProp Multi-Layer Perceptron Learner`**
- Nodo de Previsão: **`Multi-Layer Perceptron Predictor`**
- Nodo de Avaliação: **`Scorer (JavaScript)`** (classificação) ou **`Numeric Scorer`** (regressão)

**Peculiaridades do KNIME para Redes**:
- Usa **RPROP (Resilient Backpropagation)** por padrão (variante melhorada do gradient descent)
- **Normalização é obrigatória** antes de treino
- Pode definir múltiplas camadas ocultas e funções de ativação

### 🐍 Integração com Keras (Deep Learning em Python)

**Pré-requisitos**:
- TensorFlow/Keras instalado
- Dados normalizados/escalados

**Fluxo Típico**:
```python
import tensorflow as tf
from tensorflow import keras
from sklearn.preprocessing import MinMaxScaler

# 1. NORMALIZAÇÃO (CRÍTICO)
scaler = MinMaxScaler(feature_range=(0, 1))
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 2. DEFINIR MODELO
model = keras.Sequential([
    keras.layers.Dense(64, activation='relu', input_shape=(n_features,)),
    keras.layers.Dense(32, activation='relu'),
    keras.layers.Dense(16, activation='relu'),
    keras.layers.Dense(1, activation='sigmoid')  # Classificação binária
])

# 3. COMPILAR
model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

# 4. TREINAR
history = model.fit(
    X_train_scaled, y_train,
    epochs=100,
    batch_size=32,
    validation_split=0.2,
    verbose=1
)

# 5. AVALIAR
test_loss, test_acc = model.evaluate(X_test_scaled, y_test)
print(f"Test Accuracy: {test_acc}")
```

**Parâmetros Críticos**:
- **Epochs**: Número de passos completos pelo dataset
- **Batch Size**: Número de amostras antes de atualizar pesos
- **Learning Rate**: Controlado pelo optimizer ('adam' adapta automaticamente)
- **Activation Functions**:
  - `relu`: Hidden layers (não-linearidade)
  - `sigmoid`: Classificação binária
  - `softmax`: Classificação multi-classe
  - `linear`: Regressão
- **Loss Function**:
  - `binary_crossentropy`: Classificação binária
  - `categorical_crossentropy`: Multi-classe
  - `mse`: Regressão

---

## 🔗 RELAÇÕES ENTRE CONCEITOS

```
SISTEMAS DE APRENDIZAGEM
    ├─ COM SUPERVISÃO
    │  ├─ Classificação (Árvores, SVM, Redes)
    │  └─ Regressão (Linear, Logística)
    ├─ SEM SUPERVISÃO
    │  ├─ Segmentação (k-means, Hierárquico)
    │  └─ Associação (Regras)
    └─ REFORÇO

METODOLOGIAS
    ├─ CRISP-DM (6 fases)
    ├─ SEMMA (5 fases)
    └─ PMML (Representação)

PIPELINE DE UM PROJETO
    1. Estudo do Negócio → 2. Estudo dos Dados
    → 3. Preparação dos Dados
    → 4. Modelação (Técnicas: AD, Regressão, RNA)
    → 5. Avaliação (Hold-out, Cross-Validation)
    → 6. Deployment
```

---

## 📚 RESUMO DE TÉCNICAS POR PROBLEMA

| Tipo de Problema | Técnicas Recomendadas | Métrica Principal |
|------------------|----------------------|------------------|
| Classificação | Árvores, SVM, RNA Feed-Forward | Acurácia/F1 |
| Regressão | Regressão Linear, RNA | MSE/RMSE |
| Séries Temporais | RNN, LSTM, GRU | MAE/RMSE |
| Imagens | CNN | Acurácia |
| Texto/NLP | Transformer, LSTM | Perplexidade |
| Agrupamento | k-means, AGNES | Silhueta |
| Padrões | Associação, Clustering | Confiança |

---

## 🎓 CONCLUSÃO

A **Análise de Dados e Inteligência (ADI)** é um campo multidisciplinar que:
- Combina conhecimentos de estatística, programação e negócio
- Utiliza metodologias estruturadas (CRISP-DM, SEMMA)
- Aplica diversas técnicas (AD, Regressão, RNA)
- Requer avaliação rigorosa de modelos
- Evolui constantemente com novas arquiteturas (Transformers)

O sucesso de um projeto de AD depende de:
1. Compreensão clara do problema
2. Qualidade dos dados (preparação adequada)
3. Escolha correta da técnica
4. Avaliação rigorosa
5. Implementação e monitorização contínua

---

**Documento atualizado: 23 de Maio de 2026**
**Baseado em materiais do curso 2021/22**
