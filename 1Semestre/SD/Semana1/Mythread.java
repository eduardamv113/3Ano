public class MyThread extends myThread{
    public void run(){
        for(long l = 0; l < 1L << 30 ; ll++ );
        System.out.printl("Na thread");
    }
}

//nao aconselhavel usar runnable's entre threads

class Main {
    Run|Debug 
    public static void main (String [] args) throws InterruptedException{
        {
            Thread t= new MyThread();
            //t.run() <- nunca fazer
            t.start();
            //t.start() <- nao podem invocar start varias vezes
            //Thread t3= new Thread (new MyRunnable());
            //Thread t4 = new Thread (new MyRunnable());
            //t3.start()
            //t4. start()

            System.out.printl("Na main");
            t.join();
            System.out.printl("No fim");
        }
    }
}