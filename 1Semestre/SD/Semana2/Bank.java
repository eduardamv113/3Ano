import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Bank {
    
    private static class Account {
        private int balance;
        private final Lock lock = new ReentrantLock(); // Lock per account
        
        Account(int balance) { 
            this.balance = balance; 
        }
        
        int balance() { 
            lock.lock();
            try {
                return balance;
            } finally {
                lock.unlock();
            }
        }
        
        boolean deposit(int value) {
            lock.lock();
            try {
                balance += value;
                return true;
            } finally {
                lock.unlock();
            }
        }
        
        boolean withdraw(int value) {
            lock.lock();
            try {
                if (value > balance)
                    return false;
                balance -= value;
                return true;
            } finally {
                lock.unlock();
            }
        }
    }

    // Bank slots and vector of accounts
    private int slots;
    private Account[] av; 

    public Bank(int n) {
        slots = n;
        av = new Account[slots];
        for (int i = 0; i < slots; i++) {
            av[i] = new Account(0);
        }
    }

    // Account balance
    public int balance(int id) {
        if (id < 0 || id >= slots)
            return 0;
        return av[id].balance();
    }

    // Deposit
    public boolean deposit(int id, int value) {
        if (id < 0 || id >= slots)
            return false;
        return av[id].deposit(value);
    }

    // Withdraw
    public boolean withdraw(int id, int value) {
        if (id < 0 || id >= slots)
            return false;
        return av[id].withdraw(value);
    }
    
    // Transfer between accounts (with deadlock prevention)
    public boolean transfer(int from, int to, int value) {
        if (from < 0 || from >= slots || to < 0 || to >= slots || from == to)
            return false;
        
        // Acquire locks in consistent order to prevent deadlock
        Account firstLock = av[Math.min(from, to)];
        Account secondLock = av[Math.max(from, to)];
        
        firstLock.lock.lock();
        try {
            secondLock.lock.lock();
            try {
                // Check if source account has sufficient balance
                if (av[from].balance < value) {
                    return false;
                }
                // Perform transfer
                av[from].balance -= value;
                av[to].balance += value;
                return true;
            } finally {
                secondLock.lock.unlock();
            }
        } finally {
            firstLock.lock.unlock();
        }
    }
    
    // Calculate total balance across all accounts
    public int totalBalance() {
        int total = 0;
        for (int i = 0; i < slots; i++) {
            total += balance(i);
        }
        return total;
    }
}