package co.edu.corhuila.property.identity.application.port.out;

import java.time.Instant;
import java.util.UUID;

/**
 * The refresh tokens of each session (06-data/models.md, identity.refresh_token).
 * Only the SHA-256 hash of a token is ever stored (security-policy.md).
 */
public interface RefreshTokenRepository {

    void store(UUID userId, String tokenHash, Instant expiresAt, Instant now);
}
