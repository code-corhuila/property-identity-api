package co.edu.corhuila.property.identity.adapter.out.persistence;

import static co.edu.corhuila.property.identity.adapter.out.persistence.JdbcUserAccountRepository.utc;

import co.edu.corhuila.property.identity.application.port.out.RefreshTokenRepository;
import java.time.Instant;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;

/** identity.refresh_token: one row per session, the hash only. */
public class JdbcRefreshTokenRepository implements RefreshTokenRepository {

    private final JdbcTemplate jdbc;

    public JdbcRefreshTokenRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void store(UUID userId, String tokenHash, Instant expiresAt, Instant now) {
        jdbc.update("INSERT INTO identity.refresh_token (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
                userId, tokenHash, utc(expiresAt), utc(now));
    }
}
