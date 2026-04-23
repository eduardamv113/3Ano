import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.Arrays;
import java.util.HashMap;
import static java.util.Arrays.asList;

class ContactManager {
   //por aqui o controlo de concorrencia, para os objetos ficarem encapsulados 
    private HashMap<String, Contact> contacts = new HashMap<>();

    // num dos exercicios, nao me lembro qual, tivemos de por um lock
    public void update(Contact c) {
        l.lock();
        try {
            contacts.put(c.name(), c);
        } finally {
            l.unlock();
        }
    }

    // exercicio 4
    public ContactList getContacts() { 
        l.lock();
        try {
            ContactList l = new ContactList();
            for (String name : contacts.keySet())
                l.add(contacts.get(name));
                return l;
        } finally {
            l.unlock();
    }
}

class ServerWorker implements Runnable {
    private Socket socket;
    private ContactManager manager;

    public ServerWorker(Socket socket, ContactManager manager) {
        this.socket = socket;
        this.manager = manager;
    }

    // @TODO
    @Override
    public void run() { }
}


public class Server {

    public static void main (String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(12345);
        ContactManager manager = new ContactManager();
        // example pre-population
        manager.update(new Contact("John", 20, 253123321, null, asList("john@mail.com")));
        manager.update(new Contact("Alice", 30, 253987654, "CompanyInc.", asList("alice.personal@mail.com", "alice.business@mail.com")));
        manager.update(new Contact("Bob", 40, 253123456, "Comp.Ld", asList("bob@mail.com", "bob.work@mail.com")));

        while (true) {
            Socket socket = serverSocket.accept();
            Thread worker = new Thread(new ServerWorker(socket, manager));
            worker.start();
        }
    }

}
}