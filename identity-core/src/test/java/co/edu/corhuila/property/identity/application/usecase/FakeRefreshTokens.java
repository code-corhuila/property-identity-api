package co.edu.corhuila.property.identity.application.usecase;

import co.edu.corhuila.property.identity.application.port.out.RefreshTokenRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** A fake of the port for the use-case tests: rows in a list, no SQL. */
class FakeRefreshTokens implements RefreshTokenRepository {

    static final class Row {
        final UUID userId;
        final String hash;
        final Instant expiresAt;
        Instant revokedAt;

        Row(UUID userId, String hash, Instant expiresAt) {
            this.userId = userId;
            this.hash = hash;
            this.expiresAt = expiresAt;
        }
    }

    final List<Row> rows = new ArrayList<>();

    Optional<Row> find(String hash) {
        return rows.stream().filter(r -> r.hash.equals(hash)).findFirst();
    }

    @Override
    public void store(UUID userId, String tokenHash, Instant expiresAt, Instant now) {
        rows.add(new Row(userId, tokenHash, expiresAt));
    }

    @Override
    public Optional<UUID> rotate(String presentedHash, String newHash, Instant newExpiresAt, Instant now) {
        Optional<Row> row = find(presentedHash).filter(r -> r.revokedAt == null && r.expiresAt.isAfter(now));
        row.ifPresent(r -> {
            r.revokedAt = now;
            store(r.userId, newHash, newExpiresAt, now);
        });
        return row.map(r -> r.userId);
    }

    @Override
    public Optional<UUID> findRevokedOwner(String tokenHash) {
        return find(tokenHash).filter(r -> r.revokedAt != null).map(r -> r.userId);
    }

    @Override
    public void revokeAll(UUID userId, Instant now) {
        rows.stream().filter(r -> r.userId.equals(userId) && r.revokedAt == null).forEach(r -> r.revokedAt = now);
    }

    @Override
    public void revoke(String tokenHash, UUID userId, Instant now) {
        find(tokenHash).filter(r -> r.userId.equals(userId) && r.revokedAt == null).ifPresent(r -> r.revokedAt = now);
    }
}
