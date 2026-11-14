package co.edu.corhuila.property.identity.adapter.out.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.property.identity.application.port.out.EmailAlreadyRegisteredException;
import co.edu.corhuila.property.identity.application.port.out.UserAccountRepository.RegisterResult;
import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.Role;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Runs against the REAL engine with the schema of property-identity-db applied, as
 * identity_app: it also proves the grants are enough. Skipped without
 * TEST_DATABASE_URL (Annex C); scripts/test-db.sh prepares one.
 */
@EnabledIfEnvironmentVariable(named = "TEST_DATABASE_URL", matches = ".+")
class JdbcUserAccountRepositoryIntegrationTest {

    JdbcUserAccountRepository repository;
    JdbcTemplate jdbc;

    @BeforeEach
    void connect() {
        var dataSource = new DriverManagerDataSource(System.getenv("TEST_DATABASE_URL"),
                System.getenv("TEST_DATABASE_USER"), System.getenv("TEST_DATABASE_PASSWORD"));
        jdbc = new JdbcTemplate(dataSource);
        repository = new JdbcUserAccountRepository(jdbc, new TransactionTemplate(new DataSourceTransactionManager(dataSource)));
    }

    static UserAccount newAccount() {
        return UserAccount.register(new Email("it-" + UUID.randomUUID() + "@example.com"), "$2a$12$hash", "Ana Pérez");
    }

    static String newKey() {
        return "it-" + UUID.randomUUID();
    }

    @Test
    void roundTripKeepsEveryField() {
        UserAccount account = newAccount();
        assertTrue(repository.register(account, newKey()).created());

        UserAccount stored = repository.findByEmail(account.getEmail()).orElseThrow();
        assertEquals(account.getId(), stored.getId());
        assertEquals("$2a$12$hash", stored.getPasswordHash());
        assertEquals("Ana Pérez", stored.getFullName());
        assertEquals(Role.GUEST, stored.getRole());
        assertEquals(0, stored.getFailedLogins());
        assertNull(stored.getLockedUntil());
        assertEquals(account.getCreatedAt(), stored.getCreatedAt());
        assertEquals(account.getId(), repository.findById(account.getId()).orElseThrow().getId());
    }

    @Test
    void aRepeatedKeyReturnsTheFirstAccountAndStoresNothingNew() {
        String key = newKey();
        UserAccount first = newAccount();
        repository.register(first, key);

        UserAccount second = newAccount();
        RegisterResult retry = repository.register(second, key);

        assertFalse(retry.created());
        assertEquals(first.getId(), retry.account().getId());
        assertTrue(repository.findById(second.getId()).isEmpty(), "the second account was rolled back");
    }

    @Test
    void anEmailAlreadyRegisteredIsRejectedAndItsKeyIsNotKept() {
        UserAccount first = newAccount();
        repository.register(first, newKey());
        UserAccount sameEmail = UserAccount.register(first.getEmail(), "$2a$12$other", "Otra");
        String key = newKey();

        assertThrows(EmailAlreadyRegisteredException.class, () -> repository.register(sameEmail, key));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM identity.idempotency_key WHERE key = ?",
                Integer.class, key));
    }

    @Test
    void twoRequestsWithTheSameKeyAtOnceCreateOneAccount() {
        String key = newKey();
        UserAccount a = newAccount();
        UserAccount b = newAccount();
        var first = CompletableFuture.supplyAsync(() -> repository.register(a, key));
        var second = CompletableFuture.supplyAsync(() -> repository.register(b, key));
        RegisterResult ra = first.join();
        RegisterResult rb = second.join();

        assertEquals(ra.account().getId(), rb.account().getId());
        assertTrue(ra.created() ^ rb.created(), "exactly one of them created the account");
    }

    @Test
    void theFifthFailedLoginLocksTheAccountForFifteenMinutesAndResetsTheCount() {
        UserAccount account = newAccount();
        repository.register(account, newKey());
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);

        for (int i = 0; i < 4; i++) {
            repository.recordFailedLogin(account.getId(), now);
        }
        assertEquals(4, repository.findById(account.getId()).orElseThrow().getFailedLogins());
        repository.recordFailedLogin(account.getId(), now);

        UserAccount locked = repository.findById(account.getId()).orElseThrow();
        assertEquals(0, locked.getFailedLogins());
        assertEquals(now.plus(UserAccount.LOCK_DURATION), locked.getLockedUntil());
        assertTrue(locked.isLocked(now.plusSeconds(60)));
    }

    @Test
    void twoFailuresAtOnceCountAsTwoAndASuccessResetsTheCount() {
        UserAccount account = newAccount();
        repository.register(account, newKey());
        Instant now = Instant.now();
        CompletableFuture.allOf(
                CompletableFuture.runAsync(() -> repository.recordFailedLogin(account.getId(), now)),
                CompletableFuture.runAsync(() -> repository.recordFailedLogin(account.getId(), now))).join();
        assertEquals(2, repository.findById(account.getId()).orElseThrow().getFailedLogins());

        repository.recordSuccessfulLogin(account.getId(), now);
        assertEquals(0, repository.findById(account.getId()).orElseThrow().getFailedLogins());
    }

    @Test
    void aDeletedAccountIsNeverFound() {
        UserAccount account = newAccount();
        repository.register(account, newKey());
        jdbc.update("UPDATE identity.user_account SET deleted_at = now() WHERE id = ?", account.getId());

        assertTrue(repository.findById(account.getId()).isEmpty());
        assertTrue(repository.findByEmail(account.getEmail()).isEmpty());
    }

    @Test
    void theRoleChangesOnlyFromTheExpectedRole() {
        UserAccount account = newAccount();
        repository.register(account, newKey());
        Instant now = Instant.now();

        assertTrue(repository.changeRole(account.getId(), Role.GUEST, Role.HOST, now));
        assertEquals(Role.HOST, repository.findById(account.getId()).orElseThrow().getRole());
        assertFalse(repository.changeRole(account.getId(), Role.GUEST, Role.HOST, now), "already a HOST");
    }
}
