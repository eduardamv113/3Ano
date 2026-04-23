import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.ArrayList;
import java.util.List;

class Contact {
    private String name;
    private int age;
    private long phoneNumber;
    private String company;     // Pode ser null
    private ArrayList<String> emails;

    public Contact(String name, int age, long phoneNumber, String company, List<String> emails) {
        this.name = name;
        this.age = age;
        this.phoneNumber = phoneNumber;
        this.company = company;
        this.emails = new ArrayList<>(emails);
    }

    public String name() { return name; }
    public int age() { return age; }
    public long phoneNumber() { return phoneNumber; }
    public String company() { return company; }
    public List<String> emails() { return new ArrayList(emails); }

    
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(this.name).append(";");
        builder.append(this.age).append(";");
        builder.append(this.phoneNumber).append(";");
        builder.append(this.company).append(";");
        builder.append(this.emails.toString());
        builder.append("}");
        return builder.toString();
    }
//exercicio 1.
    void serialize (DataOutputStream out) throws IOException {
        out.writeUTF(this.name);
        out.writeInt(this.age);
        out.writeLong(this.phoneNumber);
        out.writeBoolean(company!=null);
        if (company != null) 
            out.writeUTF(company);
            int n = emails.size();
            out.writeInt(n); //escrever o numero de emails
        for (String email : emails) { //percorrer a lista de emails
            out.writeUTF(email); //escrever cada email
        //nao posso por aqui flush, porque se eu tiver varios contactos, so quero dar flush no final. Como no "client.java"
        //nao se pode usar o flush no meio de metodos pois assim ficava muito pesado e teriamos de estar a por em todos os lados.
        }
    }
    static contact deserialize(DataInputStream in) throws IOException {
        String name = in.readUTF();
        int age = in.readInt();
        long phoneNumber = in.readLong();
        String email = null;
        if (in.readBoolean()) {
            email = in.readUTF();
        }
        int tagsCount = in.readInt();
        ArrayList<String> tags = new ArrayList<>();
        for (int i = 0; i < tagsCount; i++) {
            tags.add(in.readUTF());
        }
        return new Contact(name, age, phoneNumber, email, tags);
    }

}
