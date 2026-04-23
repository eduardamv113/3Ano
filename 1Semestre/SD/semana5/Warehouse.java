import java.util.*;
import java.util.concurrent.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

class Warehouse {
    private Map<String, Product> map =  new HashMap<String, Product>();
    lock lock = new ReentrantLock();

    private class Product { 
        int quantity = 0; 
        Condition c = l.reCondition(); // cada produto tem a sua propria variavel de condicao}

    private Product get(String item) { //adição hashmap caso a chave nao exista
        Product p = map.get(item);
        if (p != null) return p;
        p = new Product();
        map.put(item, p);
        return p;
    }

    public void supply(String item, int quantity) {
        l.lock();
        try {
        Product p = get(item); //
        p.quantity += quantity;
        p.c.signalAll(); // acorda threads que estao a espera deste produto
        } finally {
            l.unlock();
        }
    }

    // Errado se faltar algum produto...
    public void consume(Set<String> items) {
        l.lock();
        try {
            Product[]prods = new Product[items.size()];
            int i = 0;
        for (String s : items)
            prods[i++]= get(s);

            for(;;){
                Product p = missing(prods); //verifica se falta algum produto
                if (p == null)
                    break; // se nao faltar nenhum produto sai do ciclo
                p.cond.await(); // espera pelo produto especifico, e tem um await para saber qual produto esta em falta senao sai do ciclo
            }
        
          /*for(Product p: prods){
            while (p.quantity <= 0){
                 p.cond.await(); // espera pelo produto especifico
            }*/
            for  (Product p : prods)
            p.quantity --;
        } finally {
            l.unlock();
            }
        }
}
// todas as variaveis de condição sao criadas associadas a um lock apenas (ver video yt de "conditions and lock")

}