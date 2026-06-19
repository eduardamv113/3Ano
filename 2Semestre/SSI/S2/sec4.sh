#Exercicio 1
getfacl config.txt

# file: config.txt
# owner: admin
# group: admin
#user::rw-
#group::r--
#other:---

#Exercicio 2
# Conceder permissão de leitura para o grupo seguranca no ficheiro config.txt
setfacl -m g:seguranca:r config.txt

#Exercicio 3
getfacl config.txt

# file: config.txt
# owner: admin
# group: admin
#user::rw-
#group::r--
#group:seguranca:r--
#mask::rw-
#other:---

#diferença: foi adicionada a linha "group:seguranca:r--" que permite que o grupo seguranca possa ler o ficheiro config.txt.
#A máscara "mask::rw-" significa que as permissões máximas para entradas adicionadas são r e w, impedindo x.

#Exercicio 4
su - marina
echo "config atualizado por marina" >> /dados/config.txt
cat /dados/config.txt

#cat: /dados/config.txt: Permission denied

# marina consegue escrever no ficheiro porque tem permissão 'w' através da ACL do grupo seguranca.
# não consegue ler porque a ACL do seu grupo só concede 'r' via ACL e não executa outras permissões.
# O sistema aplica as regras de ACL e não recorre às permissões de 'other'. Resultado: escrita com restrição,
# leitura negada (Permission denied).