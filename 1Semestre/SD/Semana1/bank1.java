import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock; 

//guiao 1
//exercicio 2
class Bank {

    private static class Account {
        private int balance;
        Account(int balance) { this.balance = balance; }
        int balance() { return balance; }
        boolean deposit(int value) {
            balance += value;
            return true;
        }
    }

    // Our single account, for now
    private Account savings = new Account(0);

    // Account balance
    public int balance() { //metodo que reconhece o saldo
        return savings.balance();
    }

    // Deposit
    boolean deposit(int value) { //metodo que reconhece o deposito
        return savings.deposit(value);
    }

}
 /*ao fazer um deposito sao varias intrusções e se arranjar um lock de exclusao unica nao ha interrupcoes das instruções
vamos usar a classe "java.util.concurrent.locks" -> metodos lock e unlock. 
temos duas (1 e 2)threads com lock, se nenhuma delas fez unlock entao a 2 fica bloqueada (sem gastar tempo de cpu) ate a 1 fazer unlock.
ou seja estas duas threads nao vao ser postas "uma em cima da outra" , neste caso nnenhum deposito se vai sobrepor.
se quero proteger o banco vamos utilzar um lock para o banco, nao esquecer de liberar o lock com unlock " lock trabalho unlock".
para proteger recursos compartilhados, 
impedindo que dois ou mais threads (ou processos) os acessem simultaneamente e causem condições de corrida (race conditions). */

class E2{
    public static void main(String[] args) throws InterruptedException {
        if (args.length < 3) {
            System.out.println("Usage: java E2 <N> <I> <V>");
            return;
        }

        int N = Integer.parseInt(args[0]); // Number of threads
        int I = Integer.parseInt(args[1]); // Number of iterations per thread
        int V = Integer.parseInt(args[2]); // Deposit value

        Bank bank = new Bank();
        Thread[] threads = new Thread[N];

        // Create and start threads
        for (int i = 0; i < N; i++) {
            threads[i] = new Thread(new Depositar(bank, V, I));
            threads[i].start();
        }

        // Wait for all threads to finish
        for (int i = 0; i < N; i++) {
            threads[i].join();
        }

        // Check final balance
        int expectedBalance = N * I * V;
        System.out.println("Final balance: " + bank.balance());
        System.out.println("Expected balance: " + expectedBalance);
    }
}

/* 
Padrao de como usar o lock
lock.lock();
try {
    // código que precisa ser protegido
} finally {
    lock.unlock(); // SEMPRE no finally!
}
------
Exemplo do uso do lock
antes do lock
 // Thread A: lê balance = 100
// Thread B: lê balance = 100  ← Ambas leem o mesmo valor!
// Thread A: escreve 100 + 50 = 150
// Thread B: escreve 100 + 25 = 125  ← Perdeu o depósito da Thread A!
depois com lock
// Thread A: lock.lock() ✅
// Thread B: lock.lock() ⏳ (espera)
// Thread A: balance = 100 + 50 = 150
// Thread A: lock.unlock() ✅
// Thread B: lock.lock() ✅ (agora pode prosseguir)
// Thread B: balance = 150 + 25 = 175 ✅
// Thread B: lock.unlock() ✅
------
aplicar lock e unlock 
private static class Account {
    private int balance;
    private final Lock lock = new ReentrantLock(); // 🔒 Criar o lock
    
    Account(int balance) { 
        this.balance = balance; 
    }
    
    int balance() { 
        lock.lock(); // 🔒 TRANCAR antes de ler
        try {
            return balance;
        } finally {
            lock.unlock(); // 🔓 DESTRANCAR sempre
        }
    }
    
    boolean deposit(int value) {
        lock.lock(); // 🔒 TRANCAR antes de modificar
        try { //permite , se algo der errado, executar o codigo
            balance += value;
            return true;
        } finally {
            lock.unlock(); // 🔓 DESTRANCAR sempre
        }
    }
}
 */































