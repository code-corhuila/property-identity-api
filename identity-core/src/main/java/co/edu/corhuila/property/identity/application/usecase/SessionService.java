package co.edu.corhuila.property.identity.application.usecase;

import co.edu.corhuila.property.identity.application.port.in.AuthSession;
import co.edu.corhuila.property.identity.application.port.in.Caller;
import co.edu.corhuila.property.identity.application.port.in.NotAuthenticatedException;
import co.edu.corhuila.property.identity.application.port.in.SessionUseCases.Login;
import co.edu.corhuila.property.identity.application.port.in.SessionUseCases.Logout;
import co.edu.corhuila.property.identity.application.port.in.SessionUseCases.Refresh;
import co.edu.corhuila.property.identity.application.port.out.PasswordHasher;
import co.edu.corhuila.property.identity.application.port.out.RefreshTokenRepository;
import co.edu.corhuila.property.identity.application.port.out.UserAccountRepository;
import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.lang.System.Logger.Level;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** HU-IDENT-002: log in, renew and close the session. */
public class SessionService implements Login, Refresh, Logout {

    /** One message for a wrong e-mail, a wrong password and a locked account (A07, DEC-003). */
    static final String WRONG_CREDENTIALS = "wrong e-mail or password";
    private static final System.Logger SECURITY = System.getLogger("security");

    private final UserAccountRepository accounts;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordHasher hasher;
    private final SessionIssuer sessions;
    private final Clock clock;
    /** Compared when the e-mail has no account, so both answers take as long. */
    private final String dummyHash;

    public SessionService(UserAccountRepository accounts, RefreshTokenRepository refreshTokens, PasswordHasher hasher,
                          SessionIssuer sessions, Clock clock) {
        this.accounts = accounts;
        this.refreshTokens = refreshTokens;
        this.hasher = hasher;
        this.sessions = sessions;
        this.clock = clock;
        this.dummyHash = hasher.hash("not-a-real-password-" + UUID.randomUUID());
    }

    /**
     * A locked account answers 401 without comparing the password; each wrong
     * password is counted, and the fifth locks the account for 15 minutes.
     */
    @Override
    public AuthSession login(String email, String password) {
        Instant now = clock.instant();
        Optional<UserAccount> found = accounts.findByEmail(new Email(email));
        if (found.isEmpty()) {
            hasher.matches(password, dummyHash);
            throw new NotAuthenticatedException(WRONG_CREDENTIALS);
        }
        UserAccount account = found.get();
        if (account.isLocked(now)) {
            throw new NotAuthenticatedException(WRONG_CREDENTIALS, account.getId());
        }
        if (!hasher.matches(password, account.getPasswordHash())) {
            accounts.recordFailedLogin(account.getId(), now);
            throw new NotAuthenticatedException(WRONG_CREDENTIALS, account.getId());
        }
        accounts.recordSuccessfulLogin(account.getId(), now);
        return sessions.open(account, now);
    }

    /** Rotates the token; a token already revoked revokes every session of its owner (E-12). */
    @Override
    public AuthSession refresh(String refreshToken) {
        Instant now = clock.instant();
        String presented = SessionIssuer.hash(refreshToken);
        String replacement = sessions.newRefreshToken();
        Optional<UUID> owner = refreshTokens.rotate(presented, SessionIssuer.hash(replacement),
                now.plus(SessionIssuer.REFRESH_TOKEN_TTL), now);
        if (owner.isEmpty()) {
            refreshTokens.findRevokedOwner(presented).ifPresent(userId -> {
                refreshTokens.revokeAll(userId, now);
                SECURITY.log(Level.WARNING, "action=auth.token.revoked reason=refresh-token-reuse userId={0}", userId);
            });
            throw new NotAuthenticatedException("the refresh token is invalid, expired or already used");
        }
        UserAccount account = accounts.findById(owner.get())
                .orElseThrow(() -> new NotAuthenticatedException("the account of the session does not exist"));
        return new AuthSession(sessions.accessToken(account, now), replacement,
                SessionIssuer.ACCESS_TOKEN_TTL.toSeconds(), account);
    }

    /** The access token is not revoked: it expires within the hour (E-13). */
    @Override
    public void logout(Caller caller, String refreshToken, boolean allDevices) {
        UUID userId = caller.requirePerson();
        Instant now = clock.instant();
        if (allDevices) {
            refreshTokens.revokeAll(userId, now);
        } else {
            refreshTokens.revoke(SessionIssuer.hash(refreshToken), userId, now);
        }
    }
}
