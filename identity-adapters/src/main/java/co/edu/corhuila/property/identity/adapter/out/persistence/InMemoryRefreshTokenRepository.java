package co.edu.corhuila.property.identity.adapter.out.persistence;

import co.edu.corhuila.property.identity.application.port.out.RefreshTokenRepository;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** The in-memory twin of identity.refresh_token (no DATABASE_URL). */
public class InMemoryRefreshTokenRepository implements RefreshTokenRepository {

    /** One session: whose it is, until when, and when it stopped working (null: active). */
    private static final class Row {
        final UUID userId;
        final Instant expiresAt;
        Instant revokedAt;

        Row(UUID userId, Instant expiresAt) {
            this.userId = userId;
            this.expiresAt = expiresAt;
        }
    }

    private final Map<String, Row> rows = new HashMap<>();

    @Override
    public synchronized void store(UUID userId, String tokenHash, Instant expiresAt, Instant now) {
        if (rows.putIfAbsent(tokenHash, new Row(userId, expiresAt)) != null) {
            throw new IllegalStateException("token hash already stored");
        }
    }

    @Override
    public synchronized Optional<UUID> rotate(String presentedHash, String newHash, Instant newExpiresAt, Instant now) {
        Row row = rows.get(presentedHash);
        if (row == null || row.revokedAt != null || !row.expiresAt.isAfter(now)) {
            return Optional.empty();
        }
        row.revokedAt = now;
        store(row.userId, newHash, newExpiresAt, now);
        return Optional.of(row.userId);
    }

    @Override
    public synchronized Optional<UUID> findRevokedOwner(String tokenHash) {
        Row row = rows.get(tokenHash);
        return row != null && row.revokedAt != null ? Optional.of(row.userId) : Optional.empty();
    }

    @Override
    public synchronized void revokeAll(UUID userId, Instant now) {
        rows.values().stream().filter(r -> r.userId.equals(userId) && r.revokedAt == null).forEach(r -> r.revokedAt = now);
    }

    @Override
    public synchronized void revoke(String tokenHash, UUID userId, Instant now) {
        Row row = rows.get(tokenHash);
        if (row != null && row.userId.equals(userId) && row.revokedAt == null) {
            row.revokedAt = now;
        }
    }
}
