package g8;

import java.awt.Frame;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.locks.ReentrantLock;



public class FramedConnection implements AutoCloseable {
    DataInputStream dis;
    DataOutputStream dos;
    ReentrantLock ls = new ReentrantLock();
    ReentrantLock lr = new ReentrantLock();
    Socket socket;

    public FramedConnection(Socket socket) throws IOException {
        this.dis = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        this.dos = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
        this.socket = socket;
    }

    /**
     * Send a message (byte array). First writes the length (int) then the bytes.
     */
    public void send(Frame frame) throws IOException {
        send(frame.tag, frame.data);
    }

    /**
     * Receive next message: reads int length then reads fully the byte array.
     */
    public Frame receive() throws IOException {
        lr.lock();
        try {
            int len = dis.readInt();
            int tag = dis.readInt();
            byte[] ba = new byte[len - 4];
            dis.readFully(ba);
            return new Frame(tag, ba);
        } finally {
            lr.unlock();
        }
    }
    public void close() throws IOException {
        socket.close();
    }
}
