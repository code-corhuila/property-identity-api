package co.edu.corhuila.property.identity.adapter.out.persistence;

import co.edu.corhuila.property.identity.application.port.out.EmailAlreadyRegisteredException;
import co.edu.corhuila.property.identity.application.port.out.UserAccountRepository;
import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.Role;
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
            return new RegisterResult(copy(accounts.get(first)), false);
        }
        if (accounts.values().stream().anyMatch(a -> a.getEmail().equals(account.getEmail()))) {
            throw new EmailAlreadyRegisteredException();
        }
        accounts.put(account.getId(), account);
        keys.put(idempotencyKey, account.getId());
        return new RegisterResult(copy(account), true);
    }

    @Override
    public synchronized Optional<UserAccount> findById(UUID id) {
        return Optional.ofNullable(accounts.get(id)).map(InMemoryUserAccountRepository::copy);
    }

    @Override
    public synchronized Optional<UserAccount> findByEmail(Email email) {
        return accounts.values().stream().filter(a -> a.getEmail().equals(email)).findFirst()
                .map(InMemoryUserAccountRepository::copy);
    }

    @Override
    public synchronized void recordFailedLogin(UUID id, Instant now) {
        Optional.ofNullable(accounts.get(id)).ifPresent(a -> a.recordFailedLogin(now));
    }

    @Override
    public synchronized void recordSuccessfulLogin(UUID id, Instant now) {
        Optional.ofNullable(accounts.get(id)).ifPresent(a -> a.recordSuccessfulLogin(now));
    }

    /** upgradeToHost is the only change of role the domain has. */
    @Override
    public synchronized boolean changeRole(UUID id, Role from, Role to, Instant now) {
        UserAccount account = accounts.get(id);
        if (account == null || account.getRole() != from || from != Role.GUEST || to != Role.HOST) {
            return false;
        }
        account.upgradeToHost();
        return true;
    }

    /** A reader gets its own copy, as it would from a database: changing it changes nothing stored. */
    private static UserAccount copy(UserAccount a) {
        return UserAccount.restore(a.getId(), a.getEmail(), a.getPasswordHash(), a.getFullName(), a.getRole(),
                a.getFailedLogins(), a.getLockedUntil(), a.getCreatedAt(), a.getUpdatedAt());
    }
}
