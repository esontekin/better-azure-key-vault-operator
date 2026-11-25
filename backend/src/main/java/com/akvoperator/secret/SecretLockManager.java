package com.akvoperator.secret;

import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Fixed-size striped in-process lock manager serializing create/update/delete/recover
 * operations per (vaultId, secretName) without unbounded lock map growth.
 */
@Component
public class SecretLockManager {

    private static final int STRIPE_COUNT = 256;

    private final ReentrantLock[] stripes;

    public SecretLockManager() {
        this.stripes = new ReentrantLock[STRIPE_COUNT];
        for (int i = 0; i < STRIPE_COUNT; i++) {
            this.stripes[i] = new ReentrantLock();
        }
    }

    public <T> T executeWithLock(String vaultId, String secretName, Supplier<T> action) {
        Objects.requireNonNull(vaultId, "vaultId must not be null");
        Objects.requireNonNull(secretName, "secretName must not be null");
        Objects.requireNonNull(action, "action must not be null");

        ReentrantLock lock = stripeFor(vaultId, secretName);
        lock.lock();
        try {
            return action.get();
        } finally {
            lock.unlock();
        }
    }

    private ReentrantLock stripeFor(String vaultId, String secretName) {
        String key = vaultId + "|" + secretName.toLowerCase(Locale.ROOT);
        int index = key.hashCode() & (STRIPE_COUNT - 1);
        return stripes[index];
    }
}
