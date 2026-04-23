import java.io.*;
import java.net.Socket;

// Cliente de teste: envia alguns inteiros, fecha a saída para sinalizar EOF e lê respostas do servidor.
public class SumClient {
    public static void main(String[] args) {
        String host = "localhost";
        int port = 12345;
        if (args.length >= 1) host = args[0];
        if (args.length >= 2) {
            try { port = Integer.parseInt(args[1]); } catch (NumberFormatException ignored) {}
        }

        try (Socket socket = new Socket(host, port);
             BufferedReader serverIn = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
             PrintWriter serverOut = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true)) {

            // Exemplo: enviar alguns números
            int[] nums = {10, 5, -3, 8};
            for (int n : nums) {
                serverOut.println(n);
            }

            // Fechar a saída para sinalizar EOF ao servidor (mas manter a conexão para ler respostas)
            socket.shutdownOutput();

            // Ler respostas até EOF
            String resp;
            while ((resp = serverIn.readLine()) != null) {
                System.out.println("Servidor: " + resp);
            }

        } catch (IOException e) {
            System.err.println("Erro no cliente: " + e.getMessage());
        }
    }
}
