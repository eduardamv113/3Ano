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
    }

    TaggedConnection conn;

    public Demultiplexer (TaggedConnection conn){
        this.conn = conn;
    }

    public void start(){
        new Thread(() -> {
            try{
                for(;;){
                    TaggedConnection.Frame f = conn.receive();
                    l.lock();
                    try{
                        Entry e = map.get(f.tag);
                        if (e == null) {
                            e = new Entry();
                            map.put(f.tag, e);
                        }
                        e.queue.addLast(f.data);
                        e.cond.signalAll();
                    } finally{
                        l.unlock();
                    }
                }
            } catch (IOException e){
                l.lock();
                try{
                    ioe = e;
                    for (Entry ent : map.values())
                        ent.cond.signalAll();
                } finally{
                    l.unlock();
                }
            }
        }).start();
    }

    public byte[] receive (int tag) throws IOException{
        l.lock();
        try{
            Entry e = map.get(tag);
            if(e == null){
                e = new Entry();
                map.put(tag, e);
            }
            for(;;){
                if(!e.queue.isEmpty()){
                    return e.queue.removeFirst();
                }
                if(ioe != null) throw ioe;
                try {
                    e.cond.await();
                } catch (InterruptedException ie){
                    throw new IOException("Interrupted");
                }
            }
        } finally{
            l.unlock();
        }
    }

    @Override
    public void close() throws IOException {
        conn.close();
    }

}