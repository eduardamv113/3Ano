import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class EchoClient {

    public static void main(String[] args) {
        try {
            String host = "localhost";
            int port = 12345;
            if (args.length >= 1) host = args[0];
            if (args.length >= 2) {
                try { port = Integer.parseInt(args[1]); } catch (NumberFormatException ignored) {}
            }

            try (Socket socket = new Socket(host, port);
                 BufferedReader serverIn = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                 PrintWriter serverOut = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
                 BufferedReader systemIn = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {

                String userInput;
                // Enviar cada linha digitada e ler a resposta imediata do servidor (soma acumulada)
                while ((userInput = systemIn.readLine()) != null) {
                    serverOut.println(userInput);
                    String response = serverIn.readLine();
                    if (response != null) {
                        System.out.println("Server response: " + response);
                    }
                }

                // EOF do stdin: sinalizar ao servidor que não vamos enviar mais dados
                socket.shutdownOutput();

                // Ler respostas finais do servidor (por exemplo, a média) até EOF
                String resp;
                while ((resp = serverIn.readLine()) != null) {
                    System.out.println("Server response: " + resp);
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
