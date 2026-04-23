import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class EchoServer {

    public static void main(String[] args) {
        try {
            int port = 12345;
            if (args.length >= 1) {
                try {
                    port = Integer.parseInt(args[0]);
                } catch (NumberFormatException ignored) {}
            }

            try (ServerSocket ss = new ServerSocket(port)) {
                while (true) {
                    try (Socket socket = ss.accept();
                         BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                         PrintWriter out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true)) {

                        long sum = 0L;
                        long count = 0L;
                        String line;

                        // Ler linhas até EOF (cliente fechar a saída)
                        while ((line = in.readLine()) != null) {
                            line = line.trim();
                            if (line.isEmpty()) {
                                continue;
                            }
                            try {
                                long value = Long.parseLong(line);
                                sum += value;
                                count++;
                                // responder com a soma acumulada
                                out.println(sum);
                            } catch (NumberFormatException nfe) {
                                out.println("ERROR invalid integer: " + line);
                            }
                        }

                        // Enviar média ao cliente ao receber EOF
                        if (count > 0) {
                            double avg = (double) sum / count;
                            out.println("AVERAGE " + avg);
                        } else {
                            out.println("AVERAGE NaN");
                        }
                        out.flush();

                        // socket e streams serão fechados automaticamente pelo try-with-resources
                    } catch (IOException e) {
                        System.err.println("Erro ao tratar cliente: " + e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
