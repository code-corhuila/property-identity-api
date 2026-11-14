package co.edu.corhuila.property.identity.application.port.out;

import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.Role;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * What the service needs to store accounts (06-data/models.md, identity.user_account
 * and identity.idempotency_key). Outbound adapters implement it; a deleted account
 * (deleted_at) is never found.
 */
public interface UserAccountRepository {

    /** created is false when the key was already used: the account of the first request, nothing new. */
    record RegisterResult(UserAccount account, boolean created) { }

    /**
     * Stores the account and its Idempotency-Key in one transaction (norm 5.3.8, Annex C).
     * A key already used returns its account with created=false, whatever the body.
     *
     * @throws EmailAlreadyRegisteredException if another account has the e-mail
     */
    RegisterResult register(UserAccount account, String idempotencyKey);

    Optional<UserAccount> findById(UUID id);

    Optional<UserAccount> findByEmail(Email email);

    /**
     * Counts a failed login with one atomic update, never read and written back: two
     * failures that arrive together count as two. The fifth locks the account
     * (security-rules.md A07; UserAccount.MAX_FAILED_LOGINS, LOCK_DURATION).
     */
    void recordFailedLogin(UUID id, Instant now);

    /** A successful login sets the count back to 0. */
    void recordSuccessfulLogin(UUID id, Instant now);

    /**
     * E-14: changes the role only if the account still has {@code from}, in one
     * conditional update. False when it no longer has it: of two upgrades sent
     * together, the second finds a HOST.
     */
    boolean changeRole(UUID id, Role from, Role to, Instant now);
}
