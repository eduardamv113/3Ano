import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class SumServer {
    private final int port;

    public SumServer(int port) {
        this.port = port;
    }

    public void start() {
        System.out.println("SumServer: ouvindo na porta " + port);
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                System.out.println("Aguardando cliente...");
                try (Socket client = serverSocket.accept()) {
                    System.out.println("Cliente conectado: " + client.getRemoteSocketAddress());
                    handleClient(client);
                    System.out.println("Conexão com cliente encerrada.");
                } catch (IOException e) {
                    System.err.println("Erro ao tratar cliente: " + e.getMessage());
                    // continua aceitando outros clientes
                }
            }
        } catch (IOException e) {
            System.err.println("Falha ao abrir ServerSocket: " + e.getMessage());
        }
    }

    private void handleClient(Socket socket) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
        PrintWriter out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

        long sum = 0;
        long count = 0;

        String line;
        // Ler linhas até EOF (readLine retorna null)
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) {
                // ignorar linhas em branco
                continue;
            }
            try {
                long value = Long.parseLong(line);
                sum += value;
                count++;
                out.println(sum); // responder com a soma acumulada
            } catch (NumberFormatException nfe) {
                // enviar erro e continuar
                out.println("ERROR invalid integer: " + line);
            }
        }

        // Quando chegamos aqui, cliente fechou o stream de saída (EOF)
        if (count > 0) {
            double avg = (double) sum / count;
            out.println("AVERAGE " + avg);
        } else {
            out.println("AVERAGE NaN");
        }

        // garantir flush e fechar saída do servidor para que cliente receba o que falta
        out.flush();
    }

    public static void main(String[] args) {
        int port = 12345;
        if (args.length >= 1) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException ignored) {}
        }
        new SumServer(port).start();
    }
}
