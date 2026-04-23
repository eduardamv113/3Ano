public class Intervalos {
    public static boolean isPrime (long n){
        if (n<= 1) return false;
        for (long i = 2 ; 1<n ; i++) {
            if (n % i == 0) return false;
        }
    }
}
/*se nao estiver a dividir a tarefa por todos de forma igual, não estou a aproveitar o cpu todo.
como fazer isto?
*/
//dividir o codigo em 10

public static void main(String[] args){ new*
    int nthreads = 10;
    long fatia = 1000; //dependendo da fatia onde trabalhamos estamos a lidar com complexidades diferentes.
    Tarefa[] tarefas = new Tarefa(nthreads);
    for (int i = 0; i < nthreads; i++){
        tarefas[i] = new Tarefa (n: fatia*1, m: fatia*(i+1);
    }
    var threads = new Thread[nThreads];
        for( int i = 0; i< nthreads; i++){
            threads[i] = new Thread(tarefas[i]);
            threads[i].start();
            
        }
}
/* com a implementação dos numeros impares
 * class Tarefa implements Runnable {
    private long start, end;
    
    public Tarefa(long start, long end) {
        this.start = start;
        this.end = end;
    }
    
    @Override
    public void run() {
        long count = 0;
        for (long i = start; i <= end; i++) {
            if (isPrime(i)) {
                count++;
            }
        }
        System.out.println("Thread " + Thread.currentThread().getName() + 
                          " found " + count + " primes in range [" + start + ", " + end + "]");
    }
    
    public static boolean isPrime(long n) {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;
        
        for (long i = 5; i * i <= n; i += 6) {
            if (n % i == 0 || n % (i + 2) == 0) return false;
        }
        return true;
    }
}

public class Intervalos {
    public static void main(String[] args) throws InterruptedException {
        int nthreads = 10;
        long totalRange = 10000; // Total numbers to check
        long fatia = totalRange / nthreads; // Size of each slice
        
        Tarefa[] tarefas = new Tarefa[nthreads];
        
        // Divide work among threads
        for (int i = 0; i < nthreads; i++) {
            long start = fatia * i + 1;
            long end = (i == nthreads - 1) ? totalRange : fatia * (i + 1);
            tarefas[i] = new Tarefa(start, end);
        }
        
        Thread[] threads = new Thread[nthreads];
        
        // Start all threads
        for (int i = 0; i < nthreads; i++) {
            threads[i] = new Thread(tarefas[i]);
            threads[i].start();
        }
        
        // Wait for all threads to complete
        for (int i = 0; i < nthreads; i++) {
            threads[i].join();
        }
        
        System.out.println("All threads completed!");
    }
}
 */