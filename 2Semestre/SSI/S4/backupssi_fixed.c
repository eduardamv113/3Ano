//neste guião consiste em explorar exploits relacionados com más práticas no que diz respeito a controlo de acesso.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
//4.

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
    
    // ===== MITIGAÇÃO DA VULNERABILIDADE =====
    // ANTES: O FD permanecia aberto após setuid, permitindo exploração
    // DEPOIS: Fecha o FD antes de reduzir privilégios
    close(dfd);  // ← CORREÇÃO: Fechar o file descriptor
    
    if (setuid(getuid()) == -1) {
        perror("setuid");
        exit(1);
    }
    
    argv[0] = "/bin/sh";
    argv[1] = NULL;
    execve(argv[0], argv, NULL);
    perror("execve");
    
    return 0;
}

/*
 * EXPLICAÇÃO DA CORREÇÃO:
 * 
 * VULNERABILIDADE ORIGINAL:
 * - O file descriptor dfd para /root era aberto com privilégios elevados
 * - O programa NÃO fechava este FD antes de chamar setuid()
 * - Quando execve() é chamado, o shell herda o FD aberto
 * - Um utilizador normal pode explorar este FD usando funções como:
 *   * openat(dfd, ficheiro, ...)  - abrir ficheiros em /root
 *   * unlinkat(dfd, ficheiro, ...) - apagar ficheiros
 *   * fstatat(dfd, ficheiro, ...)  - obter informações
 * - Isto viola o princípio de MENOR PRIVILÉGIO
 * 
 * CORREÇÃO IMPLEMENTADA:
 * - Adicionar close(dfd) ANTES de setuid(getuid())
 * - Isto garante que nenhum FD privilegiado é herdado pelo shell
 * - O shell agora executa com privilégios reduzidos E sem "capacidades" abertas
 * 
 * IMPACTO:
 * A vulnerabilidade de capability leaking é eliminada
 * O processo segue o princípio de MENOR PRIVILÉGIO
 * Nenhum recurso protegido pode ser explorado após a redução de privilégios
 * A segurança do sistema é restaurada
 */
