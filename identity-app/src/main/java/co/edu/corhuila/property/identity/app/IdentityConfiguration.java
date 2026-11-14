package co.edu.corhuila.property.identity.app;

import co.edu.corhuila.property.identity.adapter.in.http.AuthFilter;
import co.edu.corhuila.property.identity.adapter.in.http.CorrelationFilter;
import co.edu.corhuila.property.identity.adapter.in.http.Rs256Verifier;
import co.edu.corhuila.property.identity.adapter.out.persistence.InMemoryRefreshTokenRepository;
import co.edu.corhuila.property.identity.adapter.out.persistence.InMemoryUserAccountRepository;
import co.edu.corhuila.property.identity.adapter.out.persistence.JdbcRefreshTokenRepository;
import co.edu.corhuila.property.identity.adapter.out.persistence.JdbcUserAccountRepository;
import co.edu.corhuila.property.identity.adapter.out.security.BcryptPasswordHasher;
import co.edu.corhuila.property.identity.adapter.out.token.Rs256TokenSigner;
import co.edu.corhuila.property.identity.adapter.out.token.RsaKeys;
import co.edu.corhuila.property.identity.application.port.out.PasswordHasher;
import co.edu.corhuila.property.identity.application.port.out.RefreshTokenRepository;
import co.edu.corhuila.property.identity.application.port.out.TokenSigner;
import co.edu.corhuila.property.identity.application.port.out.UserAccountRepository;
import co.edu.corhuila.property.identity.application.usecase.AccountService;
import co.edu.corhuila.property.identity.application.usecase.SessionIssuer;
import co.edu.corhuila.property.identity.application.usecase.SessionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * Composition root: the only place that knows every concrete type. The filters
 * are registered here explicitly, in order: correlation first, so that even a
 * 401 carries its traceId.
 */
@Configuration
public class IdentityConfiguration {

    /**
     * PERSISTENCE=postgres (the default) needs DATABASE_URL, DATABASE_USER (identity_app
     * in the platform) and DATABASE_PASSWORD: without them the service does not start.
     * PERSISTENCE=memory is for tests and local development only (norm 5.5.2).
     */
    @Bean
    Storage storage(@Value("${identity.persistence:postgres}") String persistence,
                    @Value("${identity.database.url:}") String url,
                    @Value("${identity.database.user:}") String user,
                    @Value("${identity.database.password:}") String password,
                    @Value("${identity.database.pool-max:10}") int poolMax,
                    @Value("${identity.database.statement-timeout-ms:5000}") int statementTimeoutMs) {
        return Storage.connect(persistence, url, user, password, poolMax, statementTimeoutMs);
    }

    @Bean
    UserAccountRepository userAccountRepository(Storage storage) {
        return storage.inMemory() ? new InMemoryUserAccountRepository()
                : new JdbcUserAccountRepository(storage.jdbc(), storage.tx());
    }

    /** PASSWORD_HASH_COST: the bcrypt cost, 12 by default and never less (A02). */
    @Bean
    PasswordHasher passwordHasher(@Value("${identity.password-hash-cost:12}") int cost) {
        return new BcryptPasswordHasher(cost);
    }

    @Bean
    SessionService sessionService(UserAccountRepository accounts, RefreshTokenRepository refreshTokens,
                                  PasswordHasher hasher, SessionIssuer sessions) {
        return new SessionService(accounts, refreshTokens, hasher, sessions, Clock.systemUTC());
    }

    @Bean
    AccountService accountService(UserAccountRepository accounts, PasswordHasher hasher, SessionIssuer sessions) {
        return new AccountService(accounts, hasher, sessions, Clock.systemUTC());
    }

    /**
     * JWT_PUBLIC_KEY (the PEM itself; a one-line value with literal \n escapes, as
     * a .env file holds it, is accepted) or JWT_PUBLIC_KEY_FILE. Without a key
     * the service does not start.
     */
    @Bean
    Rs256Verifier tokenVerifier(@Value("${JWT_PUBLIC_KEY:}") String pem,
                                @Value("${JWT_PUBLIC_KEY_FILE:}") String file) throws IOException {
        return new Rs256Verifier(Pem.read(pem, file));
    }

    /** The same public key, for the published copy (E-15 GET /jwks). */
    @Bean
    RSAPublicKey publicKey(@Value("${JWT_PUBLIC_KEY:}") String pem,
                           @Value("${JWT_PUBLIC_KEY_FILE:}") String file) throws IOException {
        return RsaKeys.readPublic(Pem.read(pem, file));
    }

    /**
     * JWT_PRIVATE_KEY (PKCS#8 PEM, one line with \n escapes accepted) or
     * JWT_PRIVATE_KEY_FILE. Identity is the only service that holds it. The service
     * does not start without it, or when it is not the pair of JWT_PUBLIC_KEY.
     */
    @Bean
    TokenSigner tokenSigner(@Value("${JWT_PRIVATE_KEY:}") String pem,
                            @Value("${JWT_PRIVATE_KEY_FILE:}") String file, RSAPublicKey publicKey) throws IOException {
        RSAPrivateCrtKey privateKey = RsaKeys.readPrivate(Pem.read(pem, file));
        RsaKeys.requirePair(privateKey, publicKey);
        return new Rs256TokenSigner(privateKey, RsaKeys.keyId(publicKey));
    }

    @Bean
    RefreshTokenRepository refreshTokenRepository(Storage storage) {
        return storage.inMemory() ? new InMemoryRefreshTokenRepository()
                : new JdbcRefreshTokenRepository(storage.jdbc(), storage.tx());
    }

    @Bean
    SessionIssuer sessionIssuer(TokenSigner signer, RefreshTokenRepository refreshTokens) {
        return new SessionIssuer(signer, refreshTokens);
    }


    @Bean
    FilterRegistrationBean<CorrelationFilter> correlationFilter() {
        FilterRegistrationBean<CorrelationFilter> bean = new FilterRegistrationBean<>(new CorrelationFilter());
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }

    @Bean
    FilterRegistrationBean<AuthFilter> authFilter(Rs256Verifier verifier, ObjectMapper json) {
        FilterRegistrationBean<AuthFilter> bean = new FilterRegistrationBean<>(new AuthFilter(verifier, json));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return bean;
    }
}
