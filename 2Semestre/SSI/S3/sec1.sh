#!/bin/bash
set -euo pipefail

# Script para a Secção 1 (Utilizador, Grupo e Permissão)
# Implementa os exercícios 1..7 conforme enunciado do guião

echo "Exercício 1: criar ficheiros lisboa.txt, porto.txt e braga.txt"
printf "Excerto de texto: Lisboa\n" > lisboa.txt
printf "Excerto de texto: Porto\n" > porto.txt
printf "Excerto de texto: Braga\n" > braga.txt

echo -e "\nExercício 2: ver permissões de lisboa.txt"
ls -l lisboa.txt

echo -e "\nExercício 3: definir permissões para lisboa.txt (owner, group e other -> leitura e escrita)"
# equivalente a chmod 666
chmod u=rw,g=rw,o=rw lisboa.txt
ls -l lisboa.txt

echo -e "\nExercício 4: definir permissões para porto.txt (dono: leitura e execução; sem escrita)"
# Define u=rx, remove quaisquer permissões de group/other
chmod u=rx,go= porto.txt
ls -l porto.txt

echo -e "\nExercício 5: definir permissões para braga.txt (apenas o dono com leitura)"
# Define u=r e remove permissões de group/other
chmod u=r,go= braga.txt
ls -l braga.txt

echo -e "\nExercício 6: criar directorias dir1 e dir2 e ver permissões"
mkdir -p dir1 dir2
ls -ld dir1 dir2

echo -e "\nExercício 7: remover todas as permissões de execução de dir2 exceto para o dono"
# Garante que o dono tem permissão de execução e remove a permissão de execução para group/other
chmod u+rwx,go-x dir2
ls -ld dir2

echo -e "\nScript concluído."
