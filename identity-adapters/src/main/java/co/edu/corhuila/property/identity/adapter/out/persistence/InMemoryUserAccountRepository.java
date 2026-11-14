package co.edu.corhuila.property.identity.adapter.out.persistence;

import co.edu.corhuila.property.identity.application.port.out.EmailAlreadyRegisteredException;
import co.edu.corhuila.property.identity.application.port.out.UserAccountRepository;
import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Used when DATABASE_URL is empty: the HTTP tests and a quick local run. Same
 * behavior as the JDBC adapter; nothing survives a restart.
 */
public class InMemoryUserAccountRepository implements UserAccountRepository {

    private final Map<UUID, UserAccount> accounts = new HashMap<>();
    private final Map<String, UUID> keys = new HashMap<>();

    @Override
    public synchronized RegisterResult register(UserAccount account, String idempotencyKey) {
        UUID first = keys.get(idempotencyKey);
        if (first != null) {
            return new RegisterResult(accounts.get(first), false);
        }
        if (findByEmail(account.getEmail()).isPresent()) {
            throw new EmailAlreadyRegisteredException();
        }
        accounts.put(account.getId(), account);
        keys.put(idempotencyKey, account.getId());
        return new RegisterResult(account, true);
    }

    @Override
    public synchronized Optional<UserAccount> findById(UUID id) {
        return Optional.ofNullable(accounts.get(id));
    }

    @Override
    public synchronized Optional<UserAccount> findByEmail(Email email) {
        return accounts.values().stream().filter(a -> a.getEmail().equals(email)).findFirst();
    }

    @Override
    public synchronized void recordFailedLogin(UUID id, Instant now) {
        findById(id).ifPresent(a -> a.recordFailedLogin(now));
    }

    @Override
    public synchronized void recordSuccessfulLogin(UUID id, Instant now) {
        findById(id).ifPresent(a -> a.recordSuccessfulLogin(now));
    }
}
