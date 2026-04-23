//neste guião consiste em explorar exploits relacionados com más práticas no que diz respeito a controlo de acesso.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
1. Execute o programa com um utilizador normal (que não seja o root)
  Respsota: "open /root: Permission denied", pois o utilizador normal não tem permissão para aceder ao diretório /root, 
  resultando em um erro de permissão negada.

2. Analize o código (e respetivo output do programa) e identifique a vulnerabilidade relacionada com capability leaking
  Resposta: -O file descriptor dfd para root é aberto e permanece acessível mesmo após a chamada de setuid, o que pode permitir que 
  um atacante explore essa vulnerabilidade para obter acesso não autorizado a recursos do sistema. O programa nunca fecha 
  este descritor "close(dfd)", o que significa que o acesso ao diretório /root pode ser mantido mesmo após a mudança de 
  identidade do processo, representando um risco de segurança significativo.
  - Privilégios reduzidos mas capacidade mantida: Depois de executar setuid(getuid()) para reduzir os privilégios, o processo 
  ainda mantém o file descriptor aberto para root.
  - Acesso não autorizado: Um atacante pode explorar essa vulnerabilidade para acessar arquivos ou diretórios que deveriam estar
  protegidos, como o diretório /root, mesmo após a redução de privilégios, o que pode levar a uma escalada de privilégios ou 
  comprometimento do sistema.

A vulnerabilidade permite que mesmo após reduzir privilégios, o processo mantenha uma "capacidade" (file descriptor) que não deveria ter, 
violando o princípio de menor privilégio.


3. Implemente um programa que demonstre como esta vulnerabilidade pode ser explorada por um utilizador normal (sem privilégios root) para aceder a
diretorias protegidas (neste caso, /root)
  Resposta: criar exploit.c e exploit_capab.c, ambos demonstrando como um utilizador normal pode explorar a vulnerabilidade de capability leaking 
  para acessar o diretório /root, mesmo sem privilégios root. O exploit.c simula o cenário real, enquanto o exploit_capab.c 
  cria um ambiente de teste para demonstrar a exploração da vulnerabilidade. Ambos os programas devem ser compilados e executados 
  com setuid root para funcionar corretamente.

4.  Implemente uma correção para o excerto de código apresentado que mitigue a vulnerabilidade e explique em que medida o problema é resolvido.
    Resposta: A correção para o código apresentado envolve fechar o file descriptor (dfd) imediatamente após a chamada de setuid, 
    garantindo que o processo não mantenha acesso ao diretório /root após reduzir os privilégios. Isso pode ser feito adicionando 
    a linha "close(dfd);" logo após a chamada de setuid(getuid()). Com essa correção, o processo não terá mais acesso ao 
    diretório /root, mesmo que um atacante tente explorar a vulnerabilidade, mitigando assim o risco de acesso não autorizado e escalada de privilégios.

*/