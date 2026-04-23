package g8;

import java.io.IOException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.Condition;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayDeque;


public class Demultiplexer implements AutoCloseable{
    Lock l = new ReentrantLock();
    Map<Integer, Entry> map = new HashMap<>();
    IOException ioe = null;

    private class Entry{
        Condition cond = l.newCondition();
        ArrayDeque<byte[]> queue = new ArrayDeque<>();
        int waiters = 0;
    }

    private Entry get(int tag){
        Entry e = map.get(tag);
        if (e == null) {
            e = new Entry();
            map.put(tag, e);
        }
        return e;
    }
    public Demultiplexer (TaggedConnection conn){
        this.conn = conn;
    }

    public void start(){
        new Thread(() -> {
            try{
                for(;;){
                    Frame f = conn.receive();
                    l.lock();
                    try{
                        Entry e = get(f.tag);
                        e.queue.add(f.data);
                        e.cond.signal(); //seria um desperdicidio usar signalAll pois só acordo uma thread.
                    } finally{
                        l.unlock();
                    }
                }
            } catch (IOException e){
                    ioe = e;
                    for (Entry entry : map.values()){
                        entry.cond.signalAll();
                } 
            }
        }).start();
    }

    public byte[] receive (int tag) throws IOException, InterruptedException{
        l.lock();
        try{
            Entry e = get(tag);
            e.waiters += 1;
            while(e.queue.isEmpty() && ioe == null){}
                e.cond.await();
        }
        e.waiters -= 1; 
                byte[] ba = e.queue.poll();
                if(e.waiters == 0 && e.queue.isEmpty())
                    map.remove(tag);
                if(ba !=null)
                    return ba;
                else
                    throw ioe;
            }finally{
                l.unlock();
            }
    }

}