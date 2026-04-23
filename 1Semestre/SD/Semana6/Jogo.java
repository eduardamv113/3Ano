import java.util.*;
import java.util.Random;
import java.util.concurrent.locks.Condition;




public class Jogo {
    Partida participa();

    
}

interface participa{
    int numeroDeJogadores();
    String advinha (int n);

}

class JogoImpl implements Jogo{
    Lock l = new ReentrantLock();
    Condition c = l.newCondition();
    PartidaImpl partida = new PartidaImpl();
    public Partida participa(){
        l.lock();
        try {
            final PartidaImpl p = partida;



            Thread.sleep(120*1000);
            partida = new PartidaImpl();
            return p;
        } finally {
            l.unlock();
                    }
                }
            }

class PartidaImpl implements Partida{
    private int jogadores= 0;
    private int numeroSecreto;
    private boolean terminado = false;
    private Random rand = new Random();

    public PartidaImpl(int nJogadores){
        this.jogadores = nJogadores;
        this.numeroSecreto = rand.nextInt(100);
    }

    public synchronized int numeroDeJogadores(){
        return this.jogadores;
    }

    public synchronized String advinha(int n){
        if (terminado){
            return "Jogo terminado";
        }
        if (n == numeroSecreto){
            terminado = true;
            return "Acertou!";
        } else if (n < numeroSecreto){
            return "Mais alto";
        } else {
            return "Mais baixo";
        }
    }
}