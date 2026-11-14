package co.edu.corhuila.property.identity.application.port.out;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * The refresh tokens of each session (06-data/models.md, identity.refresh_token).
 * Only the SHA-256 hash of a token is ever stored (security-policy.md).
 */
public interface RefreshTokenRepository {

    void store(UUID userId, String tokenHash, Instant expiresAt, Instant now);

    /**
     * E-12: in ONE transaction, revokes the presented token if it is active and not
     * expired, and stores its replacement for the same user: no instant where both
     * work. Empty when the presented token is unknown, expired or already revoked.
     */
    Optional<UUID> rotate(String presentedHash, String newHash, Instant newExpiresAt, Instant now);

    /** The owner of a token that was already revoked: presenting it again means it was stolen. */
    Optional<UUID> findRevokedOwner(String tokenHash);

    /** Every active session of the user (reuse detection, or logout with allDevices). */
    void revokeAll(UUID userId, Instant now);

    /** One session, only if it belongs to that user. */
    void revoke(String tokenHash, UUID userId, Instant now);
}
