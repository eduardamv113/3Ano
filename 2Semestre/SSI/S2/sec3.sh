exit 

# Exercício 1 
touch readfile.c

#codigo para readfile.c
"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    FILE *input_file;
    char buffer[256];
    int line_count = 0;
    
    // Verificar se foi passado um argumento
    if (argc < 2) {
        fprintf(stderr, "Erro: necessário fornecer o nome do ficheiro\n");
        fprintf(stderr, "Uso: %s <ficheiro>\n", argv[0]);
        return 1;
    }
    
    // Abrir o ficheiro em modo leitura
    input_file = fopen(argv[1], "r");
    if (input_file == NULL) {
        fprintf(stderr, "Erro: falha ao abrir '%s'\n", argv[1]);
        return 1;
    }
    
    // Ler linhas do ficheiro
    while (fgets(buffer, sizeof(buffer), input_file) != NULL) {
        line_count++;
        printf("%d: %s", line_count, buffer);
    }
    
    // Verificar erros
    if (ferror(input_file)) {
        fprintf(stderr, "Erro durante leitura de '%s'\n", argv[1]);
        fclose(input_file);
        return 1;
    }
    
    // Fechar ficheiro
    fclose(input_file);
    
    return 0;
}
"""

# Exercício 2
sudo adduser devsecure

# Exercício 3
sudo chown userssi mycat.c
sudo chown userssi braga.txt

# Verificar mudança de dono dos ficheiros
#ls -l mycat.c braga.txt

# Exercício 4 
gcc -o mycat mycat.c ./braga.txt

# Exercício 5 
sudo chmod u+s mycat

# Verificar permissão setuid (aparece um 's' no lugar do 'x' nas permissões do proprietário)
#ls -l mycat

# Exercício 6 
gcc -o mycat mycat.c ./braga.txt

# Quando o setuid está definido, o programa mycat executa com os privilégios do seu proprietário (userssi)
# em vez dos privilégios do utilizador que o executa. Isto permite que um utilizador comum aceda a ficheiros
# que têm restrições de leitura, desde que o proprietário (userssi) tenha permissão de leitura.
# Este mecanismo é útil para permitir que utilizadores comuns executem tarefas que requeiram privilégios
# temporários específicos, sem necessitarem de acesso root completo.
