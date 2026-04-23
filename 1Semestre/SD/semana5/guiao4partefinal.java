import java.util.concurrent.lock.*;

class Barrier{
    final int N;
    int counter = 0;
    int etapa= 0;
    lock l = new ReentrantLock();
    Condition c = l.newCondition();
}

    Barrier (int N){
        this.N = N;
    }

        void await() throws InterruptedExecption {
            l.lock();
            try {
                int e = etapa;
                counter += l;
                if(counter < N){
                    while(etapa=e) {
                        c.await();
                    }
                } else {
                    c.signalAll();
                    etapa += l;
                    counter = 0;
                }

            } finally {
                l.unlock();
            }
        }