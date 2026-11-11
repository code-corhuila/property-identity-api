package co.edu.corhuila.property.identity.adapter.out.persistence;

import static co.edu.corhuila.property.identity.adapter.out.persistence.JdbcUserAccountRepository.utc;

import co.edu.corhuila.property.identity.application.port.out.RefreshTokenRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/** identity.refresh_token: one row per session, the hash only. */
public class JdbcRefreshTokenRepository implements RefreshTokenRepository {

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;

    public JdbcRefreshTokenRepository(JdbcTemplate jdbc, TransactionTemplate tx) {
        this.jdbc = jdbc;
        this.tx = tx;
    }

    @Override
    public void store(UUID userId, String tokenHash, Instant expiresAt, Instant now) {
        jdbc.update("INSERT INTO identity.refresh_token (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
                userId, tokenHash, utc(expiresAt), utc(now));
    }

    @Override
    public Optional<UUID> rotate(String presentedHash, String newHash, Instant newExpiresAt, Instant now) {
        // The UPDATE locks the row: of two renewals with the same token, the second
        // finds it already revoked, and that is treated as a reuse.
        return tx.execute(status -> {
            List<UUID> owner = jdbc.query("UPDATE identity.refresh_token SET revoked_at = ?"
                            + " WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ? RETURNING user_id",
                    (rs, n) -> rs.getObject(1, UUID.class), utc(now), presentedHash, utc(now));
            if (owner.isEmpty()) {
                return Optional.<UUID>empty();
            }
            store(owner.get(0), newHash, newExpiresAt, now);
            return Optional.of(owner.get(0));
        });
    }

    @Override
    public Optional<UUID> findRevokedOwner(String tokenHash) {
        return jdbc.query("SELECT user_id FROM identity.refresh_token WHERE token_hash = ? AND revoked_at IS NOT NULL",
                (rs, n) -> rs.getObject(1, UUID.class), tokenHash).stream().findFirst();
    }

    @Override
    public void revokeAll(UUID userId, Instant now) {
        jdbc.update("UPDATE identity.refresh_token SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                utc(now), userId);
    }

    @Override
    public void revoke(String tokenHash, UUID userId, Instant now) {
        jdbc.update("UPDATE identity.refresh_token SET revoked_at = ?"
                + " WHERE token_hash = ? AND user_id = ? AND revoked_at IS NULL", utc(now), tokenHash, userId);
    }
}
