# Exercício 0
/etc/shadow
/etc/gshadow

# Exercício 1
sudo adduser marina
sudo adduser tomás
sudo adduser diana

# Exercício 2
sudo groupadd seguranca-dev
sudo usermod -aG seguranca-dev marina
sudo usermod -aG seguranca-dev tomás
sudo usermod -aG seguranca-dev diana
sudo groupadd admin-dev
sudo usermod -aG admin-dev tomás
sudo usermod -aG admin-dev diana

# Exercício 3
# Os ficheiros /etc/shadow e /etc/gshadow contêm informações sensíveis encriptadas. A permissão permanece denied para ambos os ficheiros sem privilégios root.

# Exercício 4
sudo chown marina viseu.txt

# Exercício 5
cat viseu.txt

# Exercício 6
su - marina

# Exercício 7
#uid=1002(marina) gid=1002(marina) groups=1002(marina),100(users),1005(seguranca-dev)
#marina users seguranca-dev

# Exercício 8
#cat: viseu.txt: Permission denied
#o ficheiro viseu.txt não tem permissão de leitura para o utilizador marina, apesar de ser o proprietário.

# Exercício 9
#-bash: cd: docs2: Permission denied