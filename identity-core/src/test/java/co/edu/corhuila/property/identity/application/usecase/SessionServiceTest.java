package co.edu.corhuila.property.identity.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.property.identity.application.port.in.AccessDeniedException;
import co.edu.corhuila.property.identity.application.port.in.AuthSession;
import co.edu.corhuila.property.identity.application.port.in.Caller;
import co.edu.corhuila.property.identity.application.port.in.NotAuthenticatedException;
import co.edu.corhuila.property.identity.application.port.out.PasswordHasher;
import co.edu.corhuila.property.identity.application.port.out.UserAccountRepository;
import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.Role;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** HU-IDENT-002 at the level of the use case, with fakes of the ports. */
class SessionServiceTest {

    /** A clock the test moves forward. */
    static final class MovingClock extends Clock {
        Instant now = Instant.parse("2026-11-08T10:00:00Z");
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    /** One account in memory, with the rules of the domain. */
    final UserAccount ana = UserAccount.register(new Email("ana@example.com"), "hashed:SecurePass1", "Ana");
    final UserAccountRepository accounts = new UserAccountRepository() {
        @Override public RegisterResult register(UserAccount a, String key) { throw new UnsupportedOperationException(); }
        @Override public Optional<UserAccount> findById(UUID id) { return Optional.of(ana).filter(a -> a.getId().equals(id)); }
        @Override public Optional<UserAccount> findByEmail(Email e) { return Optional.of(ana).filter(a -> a.getEmail().equals(e)); }
        @Override public void recordFailedLogin(UUID id, Instant now) { ana.recordFailedLogin(now); }
        @Override public void recordSuccessfulLogin(UUID id, Instant now) { ana.recordSuccessfulLogin(now); }
        @Override public boolean changeRole(UUID id, Role from, Role to, Instant now) { return false; }
    };
    final AtomicInteger comparisons = new AtomicInteger();
    final PasswordHasher hasher = new PasswordHasher() {
        @Override public String hash(String password) { return "hashed:" + password; }
        @Override public boolean matches(String password, String hash) {
            comparisons.incrementAndGet();
            return hash.equals("hashed:" + password);
        }
    };
    final FakeRefreshTokens refreshTokens = new FakeRefreshTokens();
    final MovingClock clock = new MovingClock();
    final SessionService service = new SessionService(accounts, refreshTokens, hasher,
            new SessionIssuer(claims -> "access-" + claims.id(), refreshTokens), clock);
    final Caller anaCaller = new Caller(ana.getId().toString(), List.of("GUEST"), false);

    @Test
    void rightCredentialsOpenASessionAndResetTheCount() {
        assertThrows(NotAuthenticatedException.class, () -> service.login("ana@example.com", "wrong"));
        AuthSession session = service.login("ANA@example.com", "SecurePass1");

        assertNotNull(session.refreshToken());
        assertEquals(3600, session.expiresIn());
        assertEquals(0, ana.getFailedLogins());
    }

    @Test
    void wrongPasswordUnknownEmailAndLockShareOneAnswer() {
        var wrong = assertThrows(NotAuthenticatedException.class, () -> service.login("ana@example.com", "wrong"));
        var unknown = assertThrows(NotAuthenticatedException.class, () -> service.login("nadie@example.com", "x"));

        assertEquals(wrong.getMessage(), unknown.getMessage());
        assertEquals(1, ana.getFailedLogins());
    }

    @Test
    void theFifthFailureLocksForFifteenMinutesWithoutComparingThePassword() {
        for (int i = 0; i < 5; i++) {
            assertThrows(NotAuthenticatedException.class, () -> service.login("ana@example.com", "wrong"));
        }
        int before = comparisons.get();
        var locked = assertThrows(NotAuthenticatedException.class, () -> service.login("ana@example.com", "SecurePass1"));
        assertEquals(SessionService.WRONG_CREDENTIALS, locked.getMessage());
        assertEquals(before, comparisons.get(), "a locked account does not compare the password");

        clock.now = clock.now.plus(Duration.ofMinutes(15)).plusSeconds(1);
        assertNotNull(service.login("ana@example.com", "SecurePass1"), "the lock ends by itself");
    }

    @Test
    void renewalRotatesTheTokenAndTheOldOneStopsWorking() {
        AuthSession first = service.login("ana@example.com", "SecurePass1");
        AuthSession renewed = service.refresh(first.refreshToken());

        assertNotEquals(first.refreshToken(), renewed.refreshToken());
        assertNotEquals(first.accessToken(), renewed.accessToken());
        assertEquals(ana.getId(), renewed.account().getId());
        assertThrows(NotAuthenticatedException.class, () -> service.refresh(first.refreshToken()));
    }

    @Test
    void reusingARevokedTokenRevokesEverySessionOfTheAccount() {
        AuthSession phone = service.login("ana@example.com", "SecurePass1");
        AuthSession laptop = service.login("ana@example.com", "SecurePass1");
        AuthSession renewed = service.refresh(phone.refreshToken());

        assertThrows(NotAuthenticatedException.class, () -> service.refresh(phone.refreshToken()));

        assertThrows(NotAuthenticatedException.class, () -> service.refresh(renewed.refreshToken()));
        assertThrows(NotAuthenticatedException.class, () -> service.refresh(laptop.refreshToken()));
        assertTrue(refreshTokens.rows.stream().allMatch(r -> r.revokedAt != null));
    }

    @Test
    void anExpiredOrUnknownTokenIs401() {
        AuthSession session = service.login("ana@example.com", "SecurePass1");
        clock.now = clock.now.plus(SessionIssuer.REFRESH_TOKEN_TTL).plusSeconds(1);

        assertThrows(NotAuthenticatedException.class, () -> service.refresh(session.refreshToken()));
        assertThrows(NotAuthenticatedException.class, () -> service.refresh("never-issued"));
    }

    @Test
    void logoutClosesOneSessionOrAll() {
        AuthSession phone = service.login("ana@example.com", "SecurePass1");
        AuthSession laptop = service.login("ana@example.com", "SecurePass1");

        service.logout(anaCaller, phone.refreshToken(), false);
        assertThrows(NotAuthenticatedException.class, () -> service.refresh(phone.refreshToken()));

        service.logout(anaCaller, null, true);
        assertTrue(refreshTokens.findRevokedOwner(SessionIssuer.hash(laptop.refreshToken())).isPresent());
    }

    @Test
    void logoutNeverClosesTheSessionOfAnotherAccountAndRefusesAService() {
        AuthSession session = service.login("ana@example.com", "SecurePass1");

        service.logout(new Caller(UUID.randomUUID().toString(), List.of("GUEST"), false), session.refreshToken(), false);
        assertNotNull(service.refresh(session.refreshToken()), "still open");
        assertThrows(AccessDeniedException.class, () -> service.logout(new Caller("svc-workflow", null, true), null, true));
    }
}
