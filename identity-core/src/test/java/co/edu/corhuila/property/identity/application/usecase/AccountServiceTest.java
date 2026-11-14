package co.edu.corhuila.property.identity.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.property.identity.application.port.in.AccessDeniedException;
import co.edu.corhuila.property.identity.application.port.in.AccountUseCases.RegisterCommand;
import co.edu.corhuila.property.identity.application.port.in.AccountUseCases.Registration;
import co.edu.corhuila.property.identity.application.port.in.Caller;
import co.edu.corhuila.property.identity.application.port.in.NotAuthenticatedException;
import co.edu.corhuila.property.identity.application.port.out.PasswordHasher;
import co.edu.corhuila.property.identity.application.port.out.UserAccountRepository;
import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.InvalidStatusTransitionException;
import co.edu.corhuila.property.identity.domain.model.Role;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AccountServiceTest {

    /** A fake of the port, enough for the use case: no SQL, no Spring. */
    static class FakeAccounts implements UserAccountRepository {
        final Map<UUID, UserAccount> byId = new HashMap<>();
        final Map<String, UUID> keys = new HashMap<>();

        @Override
        public RegisterResult register(UserAccount account, String key) {
            if (keys.containsKey(key)) {
                return new RegisterResult(byId.get(keys.get(key)), false);
            }
            byId.put(account.getId(), account);
            keys.put(key, account.getId());
            return new RegisterResult(account, true);
        }

        /** A copy, as a database gives: changing it changes nothing stored. */
        @Override public Optional<UserAccount> findById(UUID id) {
            return Optional.ofNullable(byId.get(id)).map(a -> UserAccount.restore(a.getId(), a.getEmail(),
                    a.getPasswordHash(), a.getFullName(), a.getRole(), 0, null, a.getCreatedAt(), a.getUpdatedAt()));
        }
        @Override public Optional<UserAccount> findByEmail(Email email) { return Optional.empty(); }
        @Override public void recordFailedLogin(UUID id, Instant now) { }
        @Override public void recordSuccessfulLogin(UUID id, Instant now) { }
        @Override public boolean changeRole(UUID id, Role from, Role to, Instant now) {
            UserAccount stored = byId.get(id);
            if (stored == null || stored.getRole() != from || !allowChange) {
                return false;
            }
            byId.put(id, UserAccount.restore(id, stored.getEmail(), stored.getPasswordHash(), stored.getFullName(), to,
                    0, null, stored.getCreatedAt(), now));
            return true;
        }
        boolean allowChange = true;
    }

    static final PasswordHasher HASHER = new PasswordHasher() {
        @Override public String hash(String password) { return "hashed:" + password; }
        @Override public boolean matches(String password, String hash) { return hash.equals("hashed:" + password); }
    };

    final FakeAccounts accounts = new FakeAccounts();
    final SessionIssuer sessions = new SessionIssuer(claims -> "token", new FakeRefreshTokens());
    final AccountService service = new AccountService(accounts, HASHER, sessions,
            Clock.fixed(Instant.parse("2026-11-08T10:00:00Z"), ZoneOffset.UTC));

    @Test
    void registerStoresAGuestWithTheHashAndOpensASession() {
        Registration r = service.register(new RegisterCommand("Ana@Example.com", "SecurePass1", "Ana", "key-00001"));

        assertTrue(r.created());
        assertNotNull(r.session());
        assertEquals(Role.GUEST, r.account().getRole());
        assertEquals("ana@example.com", r.account().getEmail().value());
        assertEquals("hashed:SecurePass1", r.account().getPasswordHash());
    }

    @Test
    void aRepeatedKeyGivesTheFirstAccountAndNoSession() {
        Registration first = service.register(new RegisterCommand("ana@example.com", "SecurePass1", "Ana", "key-00001"));
        Registration again = service.register(new RegisterCommand("otra@example.com", "SecurePass1", "Otra", "key-00001"));

        assertFalse(again.created());
        assertNull(again.session());
        assertEquals(first.account().getId(), again.account().getId());
    }

    @Test
    void getMeReturnsTheAccountOfThePerson() {
        UserAccount ana = service.register(new RegisterCommand("ana@example.com", "SecurePass1", "Ana", "key-00001")).account();

        assertEquals(ana.getId(), service.getMe(new Caller(ana.getId().toString(), List.of("GUEST"), false)).getId());
    }

    @Test
    void getMeRefusesAServiceOrATokenWithoutRole() {
        assertThrows(AccessDeniedException.class, () -> service.getMe(new Caller("svc-workflow", null, true)));
        assertThrows(AccessDeniedException.class, () -> service.getMe(new Caller(UUID.randomUUID().toString(), List.of(), false)));
    }

    @Test
    void getMeOfAnUnknownOrMalformedSubjectIsNotAuthenticated() {
        assertThrows(NotAuthenticatedException.class,
                () -> service.getMe(new Caller(UUID.randomUUID().toString(), List.of("GUEST"), false)));
        assertThrows(NotAuthenticatedException.class, () -> service.getMe(new Caller("alice", List.of("GUEST"), false)));
    }

    @Test
    void everyRoleHasThePermissionsOfThePolicyAndNoCreationOfReservasOrPagos() {
        for (Role role : Role.values()) {
            assertEquals(8, role.permissions().size());
            assertFalse(role.permissions().contains("reservas:create"));
            assertFalse(role.permissions().contains("pagos:create"));
        }
    }

    Caller guest(UserAccount a) {
        return new Caller(a.getId().toString(), List.of(a.getRole().name()), false);
    }

    @Test
    void aGuestBecomesAHostOnce() {
        UserAccount ana = service.register(new RegisterCommand("ana@example.com", "SecurePass1", "Ana", "key-00001")).account();

        assertEquals(Role.HOST, service.upgradeToHost(guest(ana)).getRole());
        assertEquals(Role.HOST, accounts.byId.get(ana.getId()).getRole());
        assertThrows(InvalidStatusTransitionException.class, () -> service.upgradeToHost(guest(ana)));
    }

    @Test
    void anAdminCannotBecomeAHostAndAServiceIsRefused() {
        UUID id = UUID.randomUUID();
        UserAccount admin = UserAccount.restore(id, new Email("admin@example.com"), "h", "Admin", Role.ADMIN, 0, null,
                Instant.EPOCH, Instant.EPOCH);
        accounts.byId.put(id, admin);

        assertThrows(InvalidStatusTransitionException.class, () -> service.upgradeToHost(guest(admin)));
        assertThrows(AccessDeniedException.class, () -> service.upgradeToHost(new Caller("svc-worker", null, true)));
    }

    @Test
    void anUpgradeThatLostTheRaceIs422() {
        UserAccount ana = service.register(new RegisterCommand("ana@example.com", "SecurePass1", "Ana", "key-00001")).account();
        accounts.allowChange = false;

        assertThrows(InvalidStatusTransitionException.class, () -> service.upgradeToHost(guest(ana)));
    }
}
