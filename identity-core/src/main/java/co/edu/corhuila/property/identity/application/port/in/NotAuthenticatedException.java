package co.edu.corhuila.property.identity.application.port.in;

import java.util.Optional;
import java.util.UUID;

/**
 * The credentials do not identify an active account or session: 401 UNAUTHORIZED.
 * Wrong e-mail, wrong password and a locked account share one message (A07).
 */
public class NotAuthenticatedException extends RuntimeException {

    /** The account the attempt was against, when it exists: for the security log only, never the answer. */
    private final transient UUID accountId;

    public NotAuthenticatedException(String message) {
        this(message, null);
    }

    public NotAuthenticatedException(String message, UUID accountId) {
        super(message);
        this.accountId = accountId;
    }

    public Optional<UUID> accountId() {
        return Optional.ofNullable(accountId);
    }
}
