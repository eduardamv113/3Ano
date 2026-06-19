#Exercicio 1
getcap -r /usr/bin/

"""
Atual: =
Conjunto limitado = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
Conjunto Ambiente =
IAB Atual:
Securebits: 00/0x0/1'b0 (no-new-privs=0)
 secure-noroot: nao (desbloqueado)
 secure-no-suid-fixup: nao (desbloqueado)
 secure-keep-caps: nao (desbloqueado)
 secure-no-ambient-raise: nao (desbloqueado)
uid=1000(usuario) euid=1000(usuario)
gid=1000(usuario)
groups=4(adm),24(cdrom),27(sudo),30(dip),105(lxd),1000(usuario)
Modo inferido: HIBRIDO (4)
"""

#Exercício 2
touch network-server.c
vim network-server.c
#codigo para network-server.c
"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <porta>\n", argv[0]);
        return 1;
    }

    int porta = atoi(argv[1]);

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("Erro ao criar socket");
        return 1;
    }

    struct sockaddr_in endereco;
    memset(&endereco, 0, sizeof(endereco));
    endereco.sin_family = AF_INET;
    endereco.sin_addr.s_addr = INADDR_ANY;
    endereco.sin_port = htons(porta);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Error on bind");
        close(sockfd);
        return 1;
    }

    printf("Success: binded to port %d\n", port);
    close(sockfd);
    return 0;
}
"""
# Compilar e executar o webserver na porta 4050 (porta >= 1024, nao privilegiada)
gcc -o webserver webserver.c
./webserver 4050
# Resultado: Success: binded to port 4050
# portas >= 1024 nao requerem privilegios especiais, qualquer utilizador pode fazer bind

#Exercício 3
# Executar o webserver na porta 80 (porta privilegiada < 1024)
./webserver 80
# Resultado: Error on bind: Permission denied
# portas < 1024 sao reservadas e requerem CAP_NET_BIND_SERVICE ou root.
# O utilizador ubuntu nao tem essa capability, logo o bind e recusado pelo kernel.

# Como usar capabilities para resolver isto (sem setuid root):
# Atribuir a capability CAP_NET_BIND_SERVICE ao executavel:
sudo setcap cap_net_bind_service=+ep ./webserver

# Verificar que a capability foi atribuida:
getcap ./webserver
# Resultado: ./webserver cap_net_bind_service=ep

# Agora ja e possivel fazer bind na porta 80 sem sudo:
./webserver 80
# Resultado: Success: binded to port 80

# Vantagem face ao setuid root:
# Com setuid root, o processo ganharia TODOS os privilegios de root.
# Com CAP_NET_BIND_SERVICE, o processo ganha APENAS a capacidade de
# fazer bind em portas < 1024, respeitando o principio do menor privilegio.