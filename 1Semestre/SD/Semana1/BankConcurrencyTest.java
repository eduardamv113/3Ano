//fica 1
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

// Programa principal que testa concorrência com múltiplas threads
public class BankConcurrencyTest {
    
    public static void main(String[] args) {
        // Verificar argumentos da linha de comando
        if (args.length != 3) {
            System.out.println("Uso: java BankConcurrencyTest <N> <I> <V>");
            System.out.println("N = número de threads");
            System.out.println("I = número de depósitos por thread");
            System.out.println("V = valor de cada depósito");
            return;
        }
        
        int N = Integer.parseInt(args[0]); // número de threads
        int I = Integer.parseInt(args[1]); // depósitos por thread
        int V = Integer.parseInt(args[2]); // valor do depósito
        
        System.out.println("=== Teste de Concorrência Bancária ===");
        System.out.println("Threads: " + N);
        System.out.println("Depósitos por thread: " + I);
        System.out.println("Valor por depósito: " + V);
        System.out.println("Valor esperado final: " + (N * I * V));
        System.out.println();
        
        // Criar instância do banco
        Bank bank = new Bank();
        
        // Criar e iniciar threads
        Thread[] threads = new Thread[N];
        
        System.out.println("Iniciando " + N + " threads...");
        long startTime = System.currentTimeMillis();
        
        for (int t = 0; t < N; t++) {
            final int threadId = t;
            threads[t] = new Thread(() -> {
                System.out.println("Thread " + threadId + " iniciada");
                for (int i = 0; i < I; i++) {
                    bank.deposit(V);
                }
                System.out.println("Thread " + threadId + " finalizada");
            });
            threads[t].start();
        }
        
        // Esperar todas as threads terminarem
        try {
            for (Thread thread : threads) {
                thread.join();
            }
        } catch (InterruptedException e) {
            System.err.println("Erro ao esperar threads: " + e.getMessage());
        }
        
        long endTime = System.currentTimeMillis();
        
        // Verificar resultado
        int finalBalance = bank.balance();
        int expectedBalance = N * I * V;
        
        System.out.println();
        System.out.println("=== Resultados ===");
        System.out.println("Saldo final: " + finalBalance);
        System.out.println("Saldo esperado: " + expectedBalance);
        System.out.println("Diferença: " + (expectedBalance - finalBalance));
        System.out.println("Tempo de execução: " + (endTime - startTime) + "ms");
        
        if (finalBalance == expectedBalance) {
            System.out.println("✓ SUCESSO: Valor correto!");
        } else {
            System.out.println("✗ ERRO: Condição de corrida detectada!");
            System.out.println("Isso demonstra a necessidade de sincronização!");
        }
    }
}
