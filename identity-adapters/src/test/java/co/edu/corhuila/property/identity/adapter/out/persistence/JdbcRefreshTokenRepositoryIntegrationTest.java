package co.edu.corhuila.property.identity.adapter.out.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** identity.refresh_token against the real engine, as identity_app (TEST_DATABASE_URL, Annex C). */
@EnabledIfEnvironmentVariable(named = "TEST_DATABASE_URL", matches = ".+")
class JdbcRefreshTokenRepositoryIntegrationTest {

    JdbcTemplate jdbc;
    JdbcRefreshTokenRepository tokens;
    UUID userId;

    @BeforeEach
    void connect() {
        var dataSource = new DriverManagerDataSource(System.getenv("TEST_DATABASE_URL"),
                System.getenv("TEST_DATABASE_USER"), System.getenv("TEST_DATABASE_PASSWORD"));
        jdbc = new JdbcTemplate(dataSource);
        var tx = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        tokens = new JdbcRefreshTokenRepository(jdbc, tx);
        UserAccount account = UserAccount.register(new Email("rt-" + UUID.randomUUID() + "@example.com"), "$2a$12$h", "Ana");
        new JdbcUserAccountRepository(jdbc, tx).register(account, "rt-" + UUID.randomUUID());
        userId = account.getId();
    }

    @Test
    void storesTheHashWithItsExpiryAndNoRevocation() {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        String hash = "hash-" + UUID.randomUUID();
        tokens.store(userId, hash, now.plusSeconds(7 * 24 * 3600), now);

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT user_id, expires_at, revoked_at FROM identity.refresh_token WHERE token_hash = ?", hash);
        assertEquals(userId, row.get("user_id"));
        assertEquals(now.plusSeconds(7 * 24 * 3600), ((java.sql.Timestamp) row.get("expires_at")).toInstant());
        assertNull(row.get("revoked_at"));
    }

    @Test
    void aHashIsStoredOnlyOnce() {
        Instant now = Instant.now();
        String hash = UUID.randomUUID().toString();
        tokens.store(userId, hash, now.plusSeconds(60), now);

        assertThrows(DuplicateKeyException.class, () -> tokens.store(userId, hash, now.plusSeconds(60), now));
    }

    @Test
    void rotationRevokesTheOldTokenAndStoresTheNewOneOnce() {
        Instant now = Instant.now();
        String old = "old-" + UUID.randomUUID();
        String next = "new-" + UUID.randomUUID();
        tokens.store(userId, old, now.plusSeconds(60), now);

        assertEquals(Optional.of(userId), tokens.rotate(old, next, now.plusSeconds(120), now));
        assertEquals(Optional.of(userId), tokens.findRevokedOwner(old));
        assertTrue(tokens.findRevokedOwner(next).isEmpty());
        assertTrue(tokens.rotate(old, "again-" + UUID.randomUUID(), now.plusSeconds(120), now).isEmpty(), "single use");
    }

    @Test
    void anExpiredTokenDoesNotRotate() {
        Instant now = Instant.now();
        String hash = "exp-" + UUID.randomUUID();
        tokens.store(userId, hash, now.minusSeconds(1), now.minusSeconds(60));

        assertTrue(tokens.rotate(hash, "n-" + UUID.randomUUID(), now.plusSeconds(60), now).isEmpty());
        assertTrue(tokens.findRevokedOwner(hash).isEmpty());
    }

    @Test
    void twoRenewalsWithTheSameTokenAtOnceRotateItOnce() {
        Instant now = Instant.now();
        String hash = "race-" + UUID.randomUUID();
        tokens.store(userId, hash, now.plusSeconds(60), now);

        var a = CompletableFuture.supplyAsync(() -> tokens.rotate(hash, "a-" + UUID.randomUUID(), now.plusSeconds(60), now));
        var b = CompletableFuture.supplyAsync(() -> tokens.rotate(hash, "b-" + UUID.randomUUID(), now.plusSeconds(60), now));

        assertTrue(a.join().isPresent() ^ b.join().isPresent());
    }

    @Test
    void revokeTouchesOnlyTheOwnerAndRevokeAllEverySession() {
        Instant now = Instant.now();
        String one = "one-" + UUID.randomUUID();
        String two = "two-" + UUID.randomUUID();
        tokens.store(userId, one, now.plusSeconds(60), now);
        tokens.store(userId, two, now.plusSeconds(60), now);

        tokens.revoke(one, UUID.randomUUID(), now);
        assertTrue(tokens.findRevokedOwner(one).isEmpty(), "another user cannot close it");
        tokens.revoke(one, userId, now);
        assertEquals(Optional.of(userId), tokens.findRevokedOwner(one));

        tokens.revokeAll(userId, now);
        assertEquals(Optional.of(userId), tokens.findRevokedOwner(two));
    }
}
