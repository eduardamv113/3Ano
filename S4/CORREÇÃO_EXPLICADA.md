# COMPARAÇÃO: Código Vulnerável vs Corrigido

## CÓDIGO VULNERÁVEL (backupssi.c)

```c
int main() {
    int dfd;
    char *argv[2];
    
    dfd = open("/root", O_RDONLY);
    if (dfd == -1) {
        perror("open /root");
        exit(1);
    }
    printf("Directory FD is %d\n", dfd);
    
    if (mkdir("/root/backupssi", 0700) == -1) {
        perror("mkdir /root/backupssi");
    }
    
    // ❌ VULNERABILIDADE: FD NÃO É FECHADO!
    if (setuid(getuid()) == -1) {
        perror("setuid");
        exit(1);
    }
    
    argv[0] = "/bin/sh";
    argv[1] = NULL;
    execve(argv[0], argv, NULL);  // Shell herda FD aberto!
    perror("execve");
    
    return 0;
}
```

### Problema Identificado:
- O file descriptor `dfd` está aberto para `/root`
- `setuid()` é chamado mas o FD permanece aberto
- `execve()` é chamado, e o shell herdará o FD
- Um utilizador normal pode explorar este FD com funções relativas a file descriptors

---

## CÓDIGO CORRIGIDO (backupssi_fixed.c)

```c
int main() {
    int dfd;
    char *argv[2];
    
    dfd = open("/root", O_RDONLY);
    if (dfd == -1) {
        perror("open /root");
        exit(1);
    }
    printf("Directory FD is %d\n", dfd);
    
    if (mkdir("/root/backupssi", 0700) == -1) {
        perror("mkdir /root/backupssi");
    }
    
    // ✅ CORREÇÃO: Fechar o FD antes de reduzir privilégios
    close(dfd);  // ← LINHA CRÍTICA ADICIONADA
    
    if (setuid(getuid()) == -1) {
        perror("setuid");
        exit(1);
    }
    
    argv[0] = "/bin/sh";
    argv[1] = NULL;
    execve(argv[0], argv, NULL);  // Shell executa SEM FD privilegiado
    perror("execve");
    
    return 0;
}
```

---

## EXPLICAÇÃO DA CORREÇÃO

### O que foi alterado:
**Adição de uma única linha:** `close(dfd);`

Esta linha é inserida **ANTES** de `setuid(getuid())` para garantir que:

### Como isso resolve o problema:

1. **Elimination de Capability Leaking**
   - O FD privilegiado para `/root` é fechado explicitamente
   - Nenhuma "capacidade" permanece aberta após a redução de privilégios

2. **Princípio de Menor Privilégio**
   - O processo agora opera com os privilégios mínimos necessários
   - Nenhum recurso protegido é acessível após `setuid()`

3. **Segurança do Shell**
   - O shell executado por `execve()` não herda o FD privilegiado
   - Funções como `openat()`, `unlinkat()`, `fstatat()` não podem explorar `/root`

### Funções de Exploração Impedidas:

| Função | O que fazia | Agora |
|--------|-----------|-------|
| `openat(dfd, ...)` | Abrir ficheiros em /root | ❌ Impossível (dfd fechado) |
| `unlinkat(dfd, ...)` | Apagar ficheiros em /root | ❌ Impossível (dfd fechado) |
| `fstatat(dfd, ...)` | Obter info de ficheiros | ❌ Impossível (dfd fechado) |
| `getcwd(fd, ...)` | Aceder ao diretório | ❌ Impossível (dfd fechado) |

---

## RESUMO

| Aspecto | Antes | Depois |
|---------|-------|--------|
| **Vulnerabilidade** | Capability Leaking | ✅ Mitigada |
| **File Descriptor Aberto** | Sim, herdado pelo shell | ❌ Não, fechado com `close()` |
| **Risco de Exploração** | Alto | ✅ Eliminado |
| **Conformidade com Segurança** | ❌ Viola menor privilégio | ✅ Segue princípios corretos |

A correção implementada é **simples mas crítica**, demonstrando que mesmo uma única linha de código mal colocada pode criar vulnerabilidades graves de segurança.
