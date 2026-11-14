package co.edu.corhuila.property.identity.application.usecase;

import co.edu.corhuila.property.identity.application.port.in.AuthSession;
import co.edu.corhuila.property.identity.application.port.out.RefreshTokenRepository;
import co.edu.corhuila.property.identity.application.port.out.TokenSigner;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Opens a session for an account: an RS256 access token of 1 hour and an opaque,
 * single-use refresh token of 7 days (security-policy.md, authentication.md).
 */
public class SessionIssuer {

    public static final Duration ACCESS_TOKEN_TTL = Duration.ofHours(1);
    public static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(7);

    private final TokenSigner signer;
    private final RefreshTokenRepository refreshTokens;
    private final SecureRandom random = new SecureRandom();

    public SessionIssuer(TokenSigner signer, RefreshTokenRepository refreshTokens) {
        this.signer = signer;
        this.refreshTokens = refreshTokens;
    }

    /** Signs an access token and stores the hash of a new refresh token. */
    public AuthSession open(UserAccount account, Instant now) {
        String refreshToken = newRefreshToken();
        refreshTokens.store(account.getId(), hash(refreshToken), now.plus(REFRESH_TOKEN_TTL), now);
        return new AuthSession(accessToken(account, now), refreshToken, ACCESS_TOKEN_TTL.toSeconds(), account);
    }

    /** Claims sub, roles, iat, exp and jti; the role is the one the account has now. */
    public String accessToken(UserAccount account, Instant now) {
        return signer.sign(TokenSigner.Claims.person(account.getId().toString(), account.getRole().name(), now,
                now.plus(ACCESS_TOKEN_TTL), UUID.randomUUID().toString()));
    }

    /** 32 random bytes: a fast hash is enough to store it, and it finds the row (security-policy.md). */
    public String newRefreshToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** SHA-256 in hex: what identity.refresh_token.token_hash holds. */
    public static String hash(String refreshToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(refreshToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is always available", e);
        }
    }
}
