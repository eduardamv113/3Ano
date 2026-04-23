#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>


//ciramos um user ssihacker com 0:0, com id root e sem password, para demonstrar a vulnerabilidade de capability leaking, 
//permitindo que um utilizador normal acesse o diretório /root mesmo sem privilégios root.
//ao correr este programa conseguimos ver isto

int main() {
    int fd = open("/etc/passwd", O_WRONLY | O_APPEND);
        if (fd < 0) {
            perror("open /etc/passwd");
        exit(1);
        }
    printf("Passwd FD leaked: %d\n", fd);
    setuid(getuid());
    execl("/bin/sh", "sh", NULL);
}
