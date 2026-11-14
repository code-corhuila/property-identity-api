package co.edu.corhuila.property.identity.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * The account of a person (06-data/models.md, identity.user_account): one role,
 * a password hash never exposed, and the lock against repeated failed logins
 * (00-governance/security-rules.md, A07). Issuing tokens is not part of it.
 */
public class UserAccount {

    /** Public so the persistence adapter applies the same rule in one atomic UPDATE (models.md). */
    public static final int MAX_FAILED_LOGINS = 5;
    public static final Duration LOCK_DURATION = Duration.ofMinutes(15);
    private static final int MAX_FULL_NAME = 200;

    private final UUID id;
    private final Email email;
    private final String passwordHash;
    private final String fullName;
    private Role role;
    private int failedLogins;
    private Instant lockedUntil;
    private final Instant createdAt;
    private Instant updatedAt;

    /** Rebuilds an account the persistence adapter read: no rule runs, the data was valid when stored. */
    public static UserAccount restore(UUID id, Email email, String passwordHash, String fullName, Role role,
                                      int failedLogins, Instant lockedUntil, Instant createdAt, Instant updatedAt) {
        UserAccount account = new UserAccount(id, email, passwordHash, fullName, role, createdAt);
        account.failedLogins = failedLogins;
        account.lockedUntil = lockedUntil;
        account.updatedAt = updatedAt;
        return account;
    }

    private UserAccount(UUID id, Email email, String passwordHash, String fullName, Role role, Instant createdAt) {
        this.id = id;
        this.email = email;
        this.passwordHash = passwordHash;
        this.fullName = fullName;
        this.role = role;
        this.createdAt = createdAt;
        this.updatedAt = createdAt;
    }

    /** HU-IDENT-001: a new account is always a GUEST. */
    public static UserAccount register(Email email, String passwordHash, String fullName) {
        if (email == null) {
            throw new DomainException("El email es requerido");
        }
        if (passwordHash == null || passwordHash.isBlank()) {
            throw new DomainException("El hash de la contraseña es requerido");
        }
        if (fullName == null || fullName.isBlank() || fullName.length() > MAX_FULL_NAME) {
            throw new DomainException("El nombre completo debe tener de 1 a " + MAX_FULL_NAME + " caracteres");
        }
        // Microseconds: the precision PostgreSQL keeps, so a stored account reads back equal.
        return new UserAccount(UUID.randomUUID(), email, passwordHash, fullName.strip(), Role.GUEST,
                Instant.now().truncatedTo(ChronoUnit.MICROS));
    }

    /** E-14: only a GUEST becomes a HOST, and keeps everything a GUEST can do. */
    public void upgradeToHost() {
        if (role != Role.GUEST) {
            throw new InvalidStatusTransitionException("Solo una cuenta GUEST puede convertirse en HOST; esta es " + role);
        }
        role = Role.HOST;
        updatedAt = Instant.now();
    }

    /** A07: a locked_until in the past means the same as no lock. */
    public boolean isLocked(Instant now) {
        return lockedUntil != null && now.isBefore(lockedUntil);
    }

    /** A07: the fifth consecutive failure locks the account for 15 minutes and resets the count. */
    public void recordFailedLogin(Instant now) {
        failedLogins++;
        if (failedLogins >= MAX_FAILED_LOGINS) {
            lockedUntil = now.plus(LOCK_DURATION);
            failedLogins = 0;
        }
        updatedAt = now;
    }

    /** A07: a successful login sets the count back to 0. */
    public void recordSuccessfulLogin(Instant now) {
        failedLogins = 0;
        updatedAt = now;
    }

    public UUID getId() { return id; }
    public Email getEmail() { return email; }
    public String getPasswordHash() { return passwordHash; }
    public String getFullName() { return fullName; }
    public Role getRole() { return role; }
    public int getFailedLogins() { return failedLogins; }
    public Instant getLockedUntil() { return lockedUntil; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
