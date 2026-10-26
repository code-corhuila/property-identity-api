package co.edu.corhuila.property.identity.domain.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class UserAccountTest {

    static final Instant NOW = Instant.parse("2026-10-22T10:00:00Z");

    static UserAccount account() {
        return UserAccount.register(new Email("ana@example.com"), "$2a$12$hash", "Ana Pérez");
    }

    @Test
    void aNewAccountIsAGuest() {
        UserAccount account = account();

        assertEquals(Role.GUEST, account.getRole());
        assertEquals(0, account.getFailedLogins());
        assertNull(account.getLockedUntil());
    }

    @Test
    void registerRequiresTheHashAndAFullNameOf1To200Characters() {
        Email email = new Email("ana@example.com");
        assertThrows(DomainException.class, () -> UserAccount.register(null, "$2a$12$hash", "Ana"));
        assertThrows(DomainException.class, () -> UserAccount.register(email, " ", "Ana"));
        assertThrows(DomainException.class, () -> UserAccount.register(email, "$2a$12$hash", " "));
        assertThrows(DomainException.class, () -> UserAccount.register(email, "$2a$12$hash", "a".repeat(201)));
    }

    @Test
    void aGuestBecomesAHost() {
        UserAccount account = account();
        account.upgradeToHost();

        assertEquals(Role.HOST, account.getRole());
    }

    @Test
    void onlyAGuestBecomesAHost() {
        UserAccount account = account();
        account.upgradeToHost();

        assertThrows(InvalidStatusTransitionException.class, account::upgradeToHost);
    }

    @Test
    void theFifthConsecutiveFailureLocksTheAccountFor15Minutes() {
        UserAccount account = account();
        for (int i = 0; i < 4; i++) {
            account.recordFailedLogin(NOW);
        }
        assertFalse(account.isLocked(NOW));
        assertEquals(4, account.getFailedLogins());

        account.recordFailedLogin(NOW);

        assertTrue(account.isLocked(NOW));
        assertTrue(account.isLocked(NOW.plusSeconds(14 * 60 + 59)));
        assertFalse(account.isLocked(NOW.plusSeconds(15 * 60)));
        assertEquals(0, account.getFailedLogins());
    }

    @Test
    void aSuccessfulLoginResetsTheCount() {
        UserAccount account = account();
        account.recordFailedLogin(NOW);
        account.recordFailedLogin(NOW);
        account.recordSuccessfulLogin(NOW);

        assertEquals(0, account.getFailedLogins());
        assertFalse(account.isLocked(NOW));
    }
}
