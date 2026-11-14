package co.edu.corhuila.property.identity.application.usecase;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.property.identity.application.port.in.AuthSession;
import co.edu.corhuila.property.identity.application.port.out.RefreshTokenRepository;
import co.edu.corhuila.property.identity.application.port.out.TokenSigner;
import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class SessionIssuerTest {

    static final Instant NOW = Instant.parse("2026-11-08T10:00:00Z");

    record Stored(UUID userId, String hash, Instant expiresAt) { }

    final List<TokenSigner.Claims> signed = new ArrayList<>();
    final List<Stored> stored = new ArrayList<>();
    final TokenSigner signer = claims -> {
        signed.add(claims);
        return "signed-token";
    };
    final RefreshTokenRepository repository = new FakeRefreshTokens() {
        @Override
        public void store(UUID userId, String hash, Instant expiresAt, Instant now) {
            stored.add(new Stored(userId, hash, expiresAt));
        }
    };
    final SessionIssuer issuer = new SessionIssuer(signer, repository);
    final UserAccount ana = UserAccount.register(new Email("ana@example.com"), "$2a$12$hash", "Ana");

    @Test
    void anAccessTokenOfOneHourWithTheRoleOfTheAccount() {
        AuthSession session = issuer.open(ana, NOW);

        assertEquals("signed-token", session.accessToken());
        assertEquals(3600, session.expiresIn());
        TokenSigner.Claims claims = signed.get(0);
        assertEquals(ana.getId().toString(), claims.subject());
        assertEquals(List.of("GUEST"), claims.roles());
        assertEquals(null, claims.scope());
        assertEquals(NOW, claims.issuedAt());
        assertEquals(NOW.plusSeconds(3600), claims.expiresAt());
        assertTrue(claims.id() != null && !claims.id().isBlank());
    }

    @Test
    void onlyTheHashOfTheRefreshTokenIsStoredForSevenDays() {
        AuthSession session = issuer.open(ana, NOW);

        Stored row = stored.get(0);
        assertEquals(ana.getId(), row.userId());
        assertEquals(SessionIssuer.hash(session.refreshToken()), row.hash());
        assertNotEquals(session.refreshToken(), row.hash());
        assertTrue(row.hash().matches("[0-9a-f]{64}"));
        assertEquals(NOW.plus(SessionIssuer.REFRESH_TOKEN_TTL), row.expiresAt());
        assertEquals(NOW.plusSeconds(7 * 24 * 3600), row.expiresAt());
    }

    @Test
    void everySessionHasItsOwnRefreshTokenAndJti() {
        AuthSession first = issuer.open(ana, NOW);
        AuthSession second = issuer.open(ana, NOW);

        assertNotEquals(first.refreshToken(), second.refreshToken());
        assertNotEquals(signed.get(0).id(), signed.get(1).id());
        assertTrue(first.refreshToken().matches("[A-Za-z0-9_-]{43}"));
    }
}
