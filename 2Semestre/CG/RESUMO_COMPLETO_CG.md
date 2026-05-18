# RESUMO COMPLETO - COMPUTAÇÃO GRÁFICA

## 📋 Índice
1. [Iluminação](#iluminação)
2. [Transformações Geométricas](#transformações-geométricas)
3. [Curvas e Superfícies](#curvas-e-superfícies)
4. [Culling e Partição de Geometria](#culling-e-partição-de-geometria)
5. [Texturas](#texturas)

---

## ILUMINAÇÃO

### Fundamentos de Iluminação

#### Componentes Básicas
A intensidade de luz recebida por uma superfície depende de **3 fatores principais**:
1. **Intensidade da luz** (I)
2. **Orientação do objeto** em relação à fonte (ângulo θ)
3. **Distância à fonte de luz** (d)

#### Cálculo da Intensidade (Lei do Coseno)
```
I(d) = I₀ × cos(θ)
```
Onde:
- **I₀** = intensidade do emissor
- **θ** = ângulo de incidência entre a normal da superfície e o raio de luz
- Apenas considera-se **cos(θ) > 0**

### Componente Difusa (Reflexão Difusa - Lambert)

A intensidade refletida é **uniforme em todas as direções**:

```
I_d = K_d × I_l × max(0, n⃗ · l⃗)
```

Onde:
- **K_d** = coeficiente de reflexão difusa (0 a 1)
- **I_l** = intensidade da luz
- **n⃗** = vetor normal da superfície (normalizado)
- **l⃗** = vetor da direção da luz (normalizado)
- **n⃗ · l⃗** = produto interno (substitui cos θ se vetores normalizados)

### Componente Ambiente

Simula de forma básica as interações entre objetos e luz:

```
I_a = K_a × I_ga
```

Onde:
- **K_a** = coeficiente de reflexão ambiente
- **I_ga** = intensidade da luz ambiente global
- Afeta **todos os pontos** igualmente
- **Limitação**: não consideram relação espacial objeto-luz

### Atenuação pela Distância

#### Fórmula Física (Incorreta em CG)
```
f_att = 1 / d²
```
**Problema**: Grandes variações para luz próxima, intensidade muito pequena para luz distante.

#### Fórmula de Compromisso (Usada em CG)
```
f_att = min(1/(c₁ + c₂·d + c₃·d²), 1.0)
```

Onde:
- **c₁, c₂, c₃** = constantes da fonte de luz
- **c₁** = constante que evita denominador muito pequeno
- Garante que **f_att ≤ 1.0**

### Componente Especular - Modelo Phong

Para superfícies brilhantes, há uma mancha clara cuja posição depende da **posição do observador**:

```
I_s = K_s × I_l × max(0, cos(α))^n
```

Ou usando o **meio-vetor (Blinn-Phong)**:

```
I_s = K_s × I_l × max(0, n⃗ · h⃗)^n
```

Onde:
- **K_s** = coeficiente de especularidade (0 a 1)
- **I_l** = intensidade da luz
- **r⃗** = vetor refletido = 2(n⃗ · l⃗)n⃗ - l⃗
- **v⃗** = vetor da câmara (normalizado)
- **h⃗** = meio-vetor = (l⃗ + v⃗) / |l⃗ + v⃗|
- **n** = coeficiente de brilho (shininess) [0, 128]

#### Significado do Shininess (n)
- **n = 0.1** → mancha grande (material baço)
- **n = 128** → mancha pequena (material metálico brilhante)

### Equação Completa de Iluminação (OpenGL)

```
I_total = K_e + (K_a × I_ga) + f_att × [(K_d × I_l × max(0, n⃗ · l⃗)) + (K_s × I_l × max(0, n⃗ · h⃗)^n)]
```

Onde:
- **K_e** = cor emissiva do ponto
- **I_ga** = luz ambiente global
- **f_att** = fator de atenuação pela distância
- **Ambiente** + **Difusa** + **Especular**

### Modelos de Shading

#### 1. Flat Shading
- Uma **normal por triângulo**
- Cor calculada para **um único vértice**
- **Todo o triângulo** pintado com essa cor
- **Resultado**: Aspecto facetado muito pronunciado
- **Requisitos**: Luz infinitamente distante, câmara infinitamente distante, modelo é representação fiel da superfície

**Problema**: Bandas de Mach (disparidade entre diferença real e percepcionada de intensidade)

#### 2. Gouraud Shading (Interpolação de Cores)

**Processo**:
1. Calcular **normal por vértice** = normal média da superfície original (não do polígono)
2. Calcular **cor em cada vértice** usando equação de iluminação
3. **Interpolar cores** entre vértices para pontos interiores

**Vantagem**: Elimina aspecto facetado, luz não precisa estar infinitamente distante

**Limitações**:
- Superfície continua facetada nas arestas (normais diferentes)
- Manchas especulares não reproduzidas fielmente
- Problema: Luz circular que inclui só um canto do polígono → triângulo aparece não iluminado

#### 3. Phong Shading (Interpolação de Normais)

**Processo**:
1. Calcular **normal por vértice** = normal da superfície original
2. **Interpolar normais** entre vértices para pontos interiores
3. Calcular **cor em cada ponto** usando normal interpolada

**Vantagem**: Resolve problemas do Gouraud, manchas especulares corretas

**Desvantagem**: Mais computacionalmente intensivo (antes era problema, agora ultrapassado com shaders)

### Resumo Comparativo Shading

| Aspecto | Flat | Gouraud | Phong |
|---------|------|---------|-------|
| Normal | 1 por triângulo | 1 por vértice | 1 por vértice |
| Cálculo de cor | Vértice único | Vértice + Interpolação | Todos pontos |
| Especular | Não realista | Interpolação (artefatos) | Realista |
| Aspecto | Facetado | Suave (arestas facetadas) | Muito suave |
| Complexidade | Baixa | Média | Alta |

---

## TRANSFORMAÇÕES GEOMÉTRICAS

### Matrizes 4x4 Homogêneas (3D)

#### Matriz de Translação
```
T(t_x, t_y, t_z) = | 1  0  0  t_x |
                   | 0  1  0  t_y |
                   | 0  0  1  t_z |
                   | 0  0  0   1  |
```

#### Matriz de Escala
```
S(s_x, s_y, s_z) = | s_x  0    0    0 |
                   | 0    s_y  0    0 |
                   | 0    0    s_z  0 |
                   | 0    0    0    1 |
```

#### Matriz de Rotação em Torno do Eixo Z (ângulo θ)
```
R_z(θ) = | cos(θ)  -sin(θ)  0  0 |
         | sin(θ)   cos(θ)  0  0 |
         | 0        0       1  0 |
         | 0        0       0  1 |
```

#### Matriz de Rotação em Torno do Eixo X (ângulo θ)
```
R_x(θ) = | 1   0       0      0 |
         | 0   cos(θ) -sin(θ) 0 |
         | 0   sin(θ)  cos(θ) 0 |
         | 0   0       0      1 |
```

#### Matriz de Rotação em Torno do Eixo Y (ângulo θ)
```
R_y(θ) = | cos(θ)  0  sin(θ)  0 |
         | 0       1  0       0 |
         |-sin(θ)  0  cos(θ)  0 |
         | 0       0  0       1 |
```

### Composição de Transformações

**Ordem de Aplicação em OpenGL** (Matriz Stack):
```
M_resultado = M_ultima × M_penultima × ... × M_primeira

p' = M_resultado × p
```

**Importante**: Ordem importa! Translação + Escala ≠ Escala + Translação

### Comutatividade de Transformações

#### Comutativas:
- **Translação × Translação** ✓
  - T₁ × T₂ = T₂ × T₁

- **Escala × Escala** ✓
  - S₁ × S₂ = S₂ × S₁ (quando escalas são em torno da origem)

- **Rotação × Rotação** (em geral) ✗
  - Exceção: rotações em torno do mesmo eixo

#### Não-Comutativas:
- **Translação × Escala** ✗
  - T × S ≠ S × T

- **Translação × Rotação** ✗
  - T × R ≠ R × T

- **Rotação × Escala** ✗
  - R × S ≠ S × R

### Exemplo: Esfera Transformada

Sequência:
```
glScale(2, 2, 2);      // Escala 2x
glTranslate(1, 0, 0);  // Translação (1,0,0)
glScale(0.5, 0.5, 0.5); // Escala 0.5x
esfera();
```

**Passos**:
1. **Escala 2×**: Raio = 2, centro ainda (0,0,0)
2. **Translação**: Centro move para (1,0,0), raio = 2
3. **Escala 0.5×**: Centro permanece em (1,0,0), mas **a translação é escalada!**
   - Centro efetivo: (1×0.5, 0, 0) = (0.5, 0, 0)
   - Raio final: 2 × 0.5 = 1

### Câmara com gluLookAt

```c
gluLookAt(px, py, pz,    // Posição da câmara (eye)
          lx, ly, lz,    // Ponto para onde olha (target)
          ux, uy, uz);   // Vetor "up"
```

**Cálculo dos Vetores Base da Câmara**:

```
f⃗ = normalize(target - eye)           // Forward (direção de visão)
s⃗ = normalize(f⃗ × up)                 // Side (eixo X da câmara)
u⃗ = s⃗ × f⃗                             // Up (eixo Y da câmara, recalculado)
```

### Câmara Explorador (Coordenadas Esféricas)

Para câmara sempre a olhar para a origem com ângulos α (vertical) e β (horizontal):

```
eye_x = r × cos(α) × cos(β)
eye_y = r × sin(α)
eye_z = r × cos(α) × sin(β)

gluLookAt(eye_x, eye_y, eye_z,
          0, 0, 0,              // Centro
          0, 1, 0);             // Up
```

### Câmara FPS (First Person Shooter)

Câmara em P(x,y,z), olhando com ângulos α e β:

```
target_x = x + cos(α) × cos(β)
target_y = y + sin(α)
target_z = z + cos(α) × sin(β)

gluLookAt(x, y, z,
          target_x, target_y, target_z,
          0, 1, 0);
```

---

## CURVAS E SUPERFÍCIES

### Curvas de Bezier - Processo de De Casteljau

#### Grau 1 (Reta)
```
P(t) = (1-t)P₀ + tP₁,  0 ≤ t ≤ 1
```

#### Grau 2 (Quadrática)
```
P₁₀(t) = (1-t)P₀ + tP₁
P₁₁(t) = (1-t)P₁ + tP₂
P₂₀(t) = (1-t)P₁₀(t) + tP₁₁(t)
        = (1-t)²P₀ + 2t(1-t)P₁ + t²P₂
```

#### Grau 3 (Cúbica)
```
P(t) = (1-t)³P₀ + 3t(1-t)²P₁ + 3t²(1-t)P₂ + t³P₃
```

Onde **3 controla de De Casteljau** com **4 pontos de controle**.

### Polinômios de Bernstein

Para curva de grau n com n+1 pontos de controle:

```
B_{i,n}(t) = C(n,i) × t^i × (1-t)^(n-i)

P(t) = Σ P_i × B_{i,n}(t),  i=0 até n
```

Onde:
- **C(n,i)** = coeficiente binomial = n! / (i! × (n-i)!)
- **P_i** = ponto de controle i
- **0 ≤ t ≤ 1**

### Propriedades das Curvas de Bezier

1. **Convex Hull Property**: Curva está dentro do polígono formado pelos pontos de controle
2. **Weighted Average**: Soma de pesos (polinômios de Bernstein) = 1 para todo t
3. **Todos os pesos são positivos** → garante que ponto está "entre" controles

### Continuidade ao Unir Curvas

#### C⁰ - Continuidade de Posição
```
P₁(1) = P₂(0)
P₁³ = P₂⁰
```

#### C¹ - Continuidade de Primeira Derivada
```
P₁'(1) = P₂'(0)
P₁³ - P₁² = P₂¹ - P₂⁰
(tangentes na mesma direção)
```

#### C² - Continuidade de Segunda Derivada
Também requer continuidade da curvatura (derivada segunda).

### Derivada de Curva de Bezier Cúbica

```
P'(t) = 3[(1-t)²(P₁-P₀) + 2t(1-t)(P₂-P₁) + t²(P₃-P₂)]
```

### Curvas de Hermite Cúbica

Define curva usando:
- 2 pontos de controle (P₀, P₃)
- 2 vetores tangentes (P'₀, P'₃)

```
P(t) = [t³ t² t 1] × M_H × [P₀ P₃ P'₀ P'₃]ᵀ
```

Matriz de Hermite:
```
M_H = | 2  -2   1   1 |
      |-3   3  -2  -1 |
      | 0   0   1   0 |
      | 1   0   0   0 |
```

### Curvas de Catmull-Rom

Define curva usando 4 pontos (P₀, P₁, P₂, P₃), passando por **P₁ e P₂**:

```
P(t) = [t³ t² t 1] × M_CR × [P₀ P₁ P₂ P₃]ᵀ
```

Matriz de Catmull-Rom:
```
M_CR = |-0.5   1.5  -1.5   0.5 |
       | 1    -2.5   2    -0.5 |
       |-0.5   0     0.5   0   |
       | 0     1     0     0   |
```

### Animação com Catmull-Rom

Objeto seguindo curva em instante t:
1. **Posição**: P(t)
2. **Vetor tangente**: P'(t) = direção para onde o objeto aponta
3. **Vetor up**: (0, 1, 0) geralmente
4. **Construir matriz de rotação**:
   ```
   forward = normalize(P'(t))
   right = normalize(forward × up)
   up_final = right × forward
   
   M_rot = | right.x    right.y    right.z    0 |
           | up_final.x up_final.y up_final.z 0 |
           |-forward.x -forward.y -forward.z  0 |
           | 0         0         0           1 |
   ```

### Superfícies de Bezier (Patches)

Extensão 2D de curvas de Bezier: **4×4 pontos de controle**, 2 parâmetros (u, v):

```
P(u,v) = Σ Σ P_{i,j} × B_{i,3}(u) × B_{j,3}(v)
         i j
```

#### Cálculo de Ponto na Superfície
1. Selecionar valor u ∈ [0,1]
2. Para cada uma das 4 "curvas de controle" (u constante), calcular ponto → 4 pontos verdes
3. Esses 4 pontos verdes formam nova curva de Bezier
4. Selecionar valor v ∈ [0,1] e calcular ponto → resultado final

#### Vetores Tangentes da Superfície

```
∂P/∂u = derivada em relação a u
∂P/∂v = derivada em relação a v
```

Ambos são derivadas de polinômios de Bernstein.

#### Vetor Normal da Superfície

```
n⃗ = (∂P/∂u) × (∂P/∂v)

Normal normalizado: n̂ = n⃗ / |n⃗|
```

---

## CULLING E PARTIÇÃO DE GEOMETRIA

### Tipos de Culling

#### 1. Back Face Culling
Remove triângulos virados para longe da câmara.

**Teste**:
```
dot = n⃗ · v⃗

Se dot > 0: face visível (renderizar)
Se dot ≤ 0: face traseira (descartar)
```

Onde:
- **n⃗** = normal do triângulo
- **v⃗** = vetor de triângulo para câmara

**OpenGL**:
```c
glEnable(GL_CULL_FACE);
glCullFace(GL_BACK);           // ou GL_FRONT
glFrontFace(GL_CCW);           // contra-relógio é frente
```

**Redução**: ~50% triângulos (objetos fechados)

#### 2. View Frustum Culling
Remove objetos fora do campo de visão.

### Equação do Plano

Plano em 3D: **Ax + By + Cz + D = 0**

```
n⃗ = (A, B, C)           // Normal do plano
D = -n⃗ · p₀             // p₀ é ponto no plano
```

Distância de ponto P ao plano:
```
distance(P) = A·Px + B·Py + C·Pz + D = n⃗ · P + D
```

Se **distance > 0**: P está no lado da normal
Se **distance < 0**: P está do lado oposto
Se **distance = 0**: P está no plano

### View Frustum Setup

#### Descrição Geométrica

**Câmara com gluPerspective(fov, ratio, nearDist, farDist)**:

```
H_near = 2 × tan(fov/2) × nearDist
W_near = H_near × ratio
H_far = 2 × tan(fov/2) × farDist
W_far = H_far × ratio
```

**Pontos dos cantos (com gluLookAt)**:
- **Eye**: posição câmara
- **Direction (d)**: onde câmara aponta (normalizado)
- **Right (r)**: eixo X câmara = normalize(d × up)
- **Up (u)**: eixo Y câmara (ou recalculado)

**Cantos Near Plane**:
```
ntl = eye + d × nearDist + (H_near/2) × u - (W_near/2) × r
ntr = eye + d × nearDist + (H_near/2) × u + (W_near/2) × r
nbl = eye + d × nearDist - (H_near/2) × u - (W_near/2) × r
nbr = eye + d × nearDist - (H_near/2) × u + (W_near/2) × r
```

**Cantos Far Plane**: Similar com farDist em vez nearDist

#### 6 Planos do Frustum
1. **Near Plane** (perto câmara)
2. **Far Plane** (longe da câmara)
3. **Left Plane** (esquerda)
4. **Right Plane** (direita)
5. **Top Plane** (cima)
6. **Bottom Plane** (baixo)

### Teste de Ponto em Frustum

```c
int pointInFrustum(Vec3 p) {
    for(int i=0; i < 6; i++) {
        if (planes[i].distance(p) < 0)
            return OUTSIDE;
    }
    return INSIDE;
}
```

### Teste de Esfera em Frustum

```c
int sphereInFrustum(Vec3 center, float radius) {
    float dist;
    int result = INSIDE;
    for(int i=0; i < 6; i++) {
        dist = planes[i].distance(center);
        if (dist < -radius)
            return OUTSIDE;
        else if (dist < radius)
            result = INTERSECT;
    }
    return result;
}
```

Retorna: **OUTSIDE** (descarta), **INTERSECT** (testa conteúdo), **INSIDE** (renderiza)

### Teste de Caixa (AABB - Axis Aligned Bounding Box)

**Método n-vertex e p-vertex**:

Para cada plano com normal **n** = (n_x, n_y, n_z):

```
// P-vertex (ponto mais próximo da normal)
p.x = (n.x >= 0) ? box.max.x : box.min.x
p.y = (n.y >= 0) ? box.max.y : box.min.y
p.z = (n.z >= 0) ? box.max.z : box.min.z

// N-vertex (ponto mais distante da normal)
n.x = (n.x >= 0) ? box.min.x : box.max.x
n.y = (n.y >= 0) ? box.min.y : box.max.y
n.z = (n.z >= 0) ? box.min.z : box.max.z

// Teste
if (planes[i].distance(p) < 0)     return OUTSIDE;
if (planes[i].distance(n) < 0)     result = INTERSECT;
```

### Espaço de Clip vs Espaço Global

#### Clip Space Testing
Ponto visível em clip space: **-w' < x', y', z' < w'**

```
Matriz de transformação: A = P × M
(P = projeção, M = modelview)

p' = A × p   (ponto em clip space)

Após perspectiva divide:
p_norm = p' / w'

Visível se: -1 < p_norm.x, y, z < 1
```

#### Global Space Testing
Extrair planos diretamente da matriz A:

```
Left plane:    x(a₁₁+a₄₁) + y(a₁₂+a₄₂) + z(a₁₃+a₄₃) + w(a₁₄+a₄₄) = 0
Right plane:   x(a₄₁-a₁₁) + y(a₄₂-a₁₂) + z(a₄₃-a₁₃) + w(a₄₄-a₁₄) = 0
Bottom plane:  x(a₂₁+a₄₁) + y(a₂₂+a₄₂) + z(a₂₃+a₄₃) + w(a₂₄+a₄₄) = 0
Top plane:     x(a₄₁-a₂₁) + y(a₄₂-a₂₂) + z(a₄₃-a₂₃) + w(a₄₄-a₂₄) = 0
Near plane:    x(a₃₁+a₄₁) + y(a₃₂+a₄₂) + z(a₃₃+a₄₃) + w(a₃₄+a₄₄) = 0
Far plane:     x(a₄₁-a₃₁) + y(a₄₂-a₃₂) + z(a₄₃-a₃₃) + w(a₄₄-a₃₄) = 0
```

### Otimizações

#### Coherência Translação-Rotação
Se objeto rejeitado por plano esquerdo e câmara roda direita → permanece fora.

#### Coerência Temporal
Guardar plano que rejeitou objeto, testar esse primeiro no frame seguinte.

### Volumes Envolventes (Bounding Volumes)

#### Tipos Comuns

1. **AABB** (Axis-Aligned Bounding Box)
   - 6 planes (paralelos aos eixos)
   - Complexidade: Baixa
   - Tightness: Baixa (muito espaço vazio)

2. **OBB** (Object-Aligned Bounding Box)
   - 6 planes (alinhados com objeto)
   - Complexidade: Média
   - Tightness: Média

3. **Sphere** (Esfera)
   - Centro + raio
   - Complexidade: Muito baixa
   - Tightness: Baixa (cantos desperdiçados)

4. **Convex Hull** (Envolvente Convexa)
   - Múltiplos planes
   - Complexidade: Alta
   - Tightness: Alta (ajusta bem)

#### Hierarquias de Bounding Volumes (BVH)

Estrutura em árvore onde cada nó é volume que contém filhos.

**Vantagem**: Rejeição rápida de grandes conjuntos
**Processo**: Se nó rejeitado, toda subárvore rejeitada (sem testar filhos)

### Partição Espacial (Space Partitioning)

#### BSP (Binary Space Partition)

Divide espaço recursivamente com **planos arbitrários**.

**Estrutura**: **Árvore binária**

**Processo**:
1. Selecionar plano divisor
2. Triângulos à frente → subárvore direita
3. Triângulos atrás → subárvore esquerda
4. Triângulos atravessados → dividir e distribuir

**Aplicação**: Ordenação triângulos para transparency blending
- Traversal ordem: atrás → plano → frente (relativo à câmara)

**Problema**: Escolher bom plano divisor é NP-hard

#### K-d Trees

BSP com **planos perpendiculares aos eixos**.

**Processo**:
1. Escolher eixo (x, y, ou z)
2. Dividir com plano perpendicular a esse eixo
3. Próximo nível: trocar eixo (ciclar x → y → z)
4. Repetir recursivamente

**Vantagem**: Mais estruturado que BSP, mais fácil de implementar

#### Quadtrees (2D) / Octrees (3D)

Divide espaço em **4 (quad) ou 8 (oct) regiões iguais**.

**Quadtree**:
```
     +---+---+
     | 0 | 1 |
     +---+---+
     | 2 | 3 |
     +---+---+
```

**Octree** (3D): 8 cubos (4 acima, 4 abaixo)

**Vantagem**: Subdivisão uniforme, fácil de implementar
**Desvantagem**: Menos flexível, pode ficar desbalanceado

### Critérios para Parar Recursão

1. **Cell polygon count** atinge threshold
2. **Tree depth** muito grande
3. **Cell size** muito pequena
4. Apenas 1 triângulo

### Tratamento de Triângulos em Múltiplas Células

Opções:
1. **Incluir na célula pai** 
   - Vantagem: Simplicidade
   - Desvantagem: Perdeu particionamento fino

2. **Incluir em todas as células**
   - Vantagem: Particionamento ótimo
   - Desvantagem: Redundância, mais memória

3. **Dividir em partes**
   - Vantagem: Sem redundância, particionamento fino
   - Desvantagem: Custo computacional, mais triângulos

### BVH vs Space Partitioning

**BVH**:
- Encaixa bem objetos
- Espaço redundante (volumes podem sobrepor)
- Múltiplos objetos num volume

**Space Partitioning**:
- Encaixa bem espaço
- Objetos redundantes (podem estar em múltiplas células)
- Múltiplas células num objeto

### Masking Otimizado (Assarsson e Möller)

Se objeto **completamente dentro** de um plano:
- Todos os filhos também estarão dentro → **não testar esse plano novamente**

---

## TEXTURAS

### Componentes da Cor de Materiais (OpenGL)

1. **Ambient** (K_a): Iluminação ambiente
2. **Diffuse** (K_d): Reflexão difusa
3. **Specular** (K_s): Reflexão especular
4. **Shininess** (n): Brilho do material
5. **Emissive** (K_e): Luz emitida pelo material

### Transparência Total (Alpha Test)

Teste canal alpha (α) de cada pixel:

```c
if (alpha >= threshold)
    draw pixel;
else
    discard pixel;
```

**Vantagem**: Simples, sem sorting
**Uso**: Texturas binárias (dentro/fora)

### Transparência Parcial (Alpha Blending)

Necessário **ordenar triângulos** por distância:

```
Cor_final = Cor_triângulo × alpha + Cor_background × (1 - alpha)
```

**Ordem necessária**: **Distante para próximo**

Explicação: Se renderizar próximo primeiro, depois distante com alpha, distante "apaga" parte do próximo (incorreto).

**Problema**: Cycles (A sobre B, B sobre C, C sobre A) → sem ordem correta

### Problema de Amostragem (Aliasing)

**Oversampling**: Textura maior que pixels → múltiplos texels por pixel
- Resultado: Aliasing, padrões moiré

**Undersampling**: Textura menor que pixels → múltiplos pixels por texel
- Resultado: Pixelização, perda de detalhe

### Filtros de Textura

#### GL_NEAREST (Point Sampling)
```
Cor = texel mais próximo do (u,v)
```
- Rápido, pixelado
- Bom para arte pixel

#### GL_LINEAR (Bilinear Filtering)
```
Cor = interpolação linear dos 4 texels vizinhos
```
- Suave, sem aliasing forte
- Mais lento que NEAREST

### Mipmapping

Pré-compute **múltiplos níveis** de textura reduzida:
```
LOD 0: 512×512 (original)
LOD 1: 256×256
LOD 2: 128×128
LOD 3: 64×64
...
LOD n: 1×1
```

**Seleção automática de LOD**:
```
LOD = log₂(pixel_footprint_size / texel_size)
```

**Vantagens**:
- Elimina aliasing
- Mais rápido (menos texels a amostrar)

**Desvantagens**:
- 33% mais memória (1 + 1/4 + 1/16 + ... = 4/3 original)
- Pré-processamento

**Filtros Mipmap**:
- GL_NEAREST_MIPMAP_NEAREST
- GL_LINEAR_MIPMAP_NEAREST
- GL_NEAREST_MIPMAP_LINEAR
- GL_LINEAR_MIPMAP_LINEAR

### Mapeamento de Textura em Quad

Coordenadas de textura (u, v) ∈ [0, 1]:

```c
glBindTexture(GL_TEXTURE_2D, textureID);
glBegin(GL_QUADS);
glTexCoord2f(0, 1);  glVertex3f(x1, y1, z1);  // Cantos quadrado
glTexCoord2f(1, 1);  glVertex3f(x2, y2, z2);
glTexCoord2f(1, 0);  glVertex3f(x3, y3, z3);
glTexCoord2f(0, 0);  glVertex3f(x4, y4, z4);
glEnd();
```

(0,0) = canto inferior esquerdo
(1,1) = canto superior direito

---

## FICHAS DE CONSOLIDAÇÃO - QUESTÕES IMPORTANTES

### Transformações Geométricas

**Q: Ordem de transformações importa?**
Sim! Em OpenGL, transformações aplicadas em **ordem inversa** do código.

**Q: Como compor T × S?**
Resultado depende da ordem. T × S ≠ S × T (em geral).

**Q: Matriz 2D com transformação?**
```
| a  b  tx |
| c  d  ty |
| 0  0  1  |
```
Aplicar a ponto (x,y): (x',y') = (ax+by+tx, cx+dy+ty)

### Iluminação

**Q: Quando usar Flat vs Gouraud vs Phong?**
- Flat: Objetos simples, distante, sem especular
- Gouraud: Muitos triângulos, barato, OK para difusa
- Phong: Qualidade máxima, especular importante

**Q: Como calcular normal para iluminação?**
- Normal = média (normalizada) das normais dos triângulos adjacentes

**Q: Posição luz antes ou depois gluLookAt?**
Antes de gluLookAt → coordenadas globais
Depois de gluLookAt → coordenadas da câmara

### Curvas e Superfícies

**Q: Bezier passa por pontos de controle?**
Passa só pelos 1º e último pontos. Intermediários influenciam apenas a curvatura.

**Q: Como garantir C¹ continuidade ao unir Bezier?**
Último ponto da 1ª curva = primeiro da 2ª (C⁰)
MAIS: Vetores tangentes na mesma direção (C¹)

**Q: Como animar objeto em Catmull-Rom?**
1. Calcular P(t) (posição)
2. Calcular P'(t) (tangente = forward)
3. Construir up vector
4. Computar right = forward × up
5. Montar matriz rotação

### Culling

**Q: Qual a complexidade de cada tipo?**
- Back Face: O(n) (1 dot product por triângulo)
- View Frustum: O(n) com BVH (log n com BVH bem feita)
- Partição espacial: O(log n) médio

**Q: AABB vs Esfera?**
- AABB: Mais tight, mas 6 testes
- Esfera: Menos tight, mas 1 teste (mais rápido)

**Q: Como ordenar para BSP?**
Traversar atrás-primeiro: atrás → frente (relativo à câmara)

### Texturas

**Q: Quando usar mipmapping?**
Sempre que textura pode estar longe ou em ângulo agudo.

**Q: Qual filtro usar?**
- Próximo: LINEAR ou LINEAR_MIPMAP_LINEAR
- Distante: NEAREST_MIPMAP_LINEAR (balance)

**Q: Transparência: blending vs alpha test?**
- Alpha test: Binário (dentro/fora), sem ordem
- Blending: Parcial, requer sorting

---

## REFERÊNCIAS RÁPIDAS

### Coordenadas Padrão (OpenGL)
- X: Direita
- Y: Cima
- Z: Para fora (câmara aponta para -Z)

### Vetores Normalizados
Quando posível, sempre normalizar:
- Reduz erros de precisão
- Simplifica equações (dot product = cos θ)

### Ordem Renderização (Transparência)
**Longe → Próximo** (back-to-front)

### Matriz Stack (OpenGL)
Multiplica **direita-esquerda**: últimas multiplicações aplicadas primeiro

---

**Preparado para o teste! Boa sorte! 🎓**
