package co.edu.corhuila.property.identity.adapter.out.persistence;

import co.edu.corhuila.property.identity.application.port.out.RefreshTokenRepository;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/** The in-memory twin of identity.refresh_token (no DATABASE_URL): hash to owner. */
public class InMemoryRefreshTokenRepository implements RefreshTokenRepository {

    private final Map<String, UUID> owners = new HashMap<>();

    @Override
    public synchronized void store(UUID userId, String tokenHash, Instant expiresAt, Instant now) {
        if (owners.putIfAbsent(tokenHash, userId) != null) {
            throw new IllegalStateException("token hash already stored");
        }
    }
}
