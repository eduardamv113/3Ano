//guiao 1
//exercicio 1

class Increment implemnts Runnable {
    public void run(){
        final long i = 100;
        for (long i = 0 ; i< 100; i++)
        {
            System.out.printl(i); 
        }
    }
}

class Increment implements Runnable
{
    public void run()
    {
        final long I = 100;
        for(long i = 0; i < I; i++)
        {
            System.out.println(i);
        }
    }
}

class E1
{
    public static void main(String[] args) throws InterruptedException {
        final int N = 10;
        Thread[] a = new Thread[N];
        for(int i = 0; i < N; i++)
        {
            a[i] = new Thread(new Increment());
            a[i].start(); // Start each thread
        }

        for(int i = 0; i < N; i++)
        {
            a[i].join(); // Wait for all threads to finish
        }

        System.out.println("Fim");
    }
}