package co.edu.corhuila.property.identity.app;

import co.edu.corhuila.property.identity.adapter.out.token.Rs256TokenSigner;
import co.edu.corhuila.property.identity.adapter.out.token.RsaKeys;
import co.edu.corhuila.property.identity.application.usecase.ServiceTokenIssuer;
import java.io.IOException;
import java.io.PrintStream;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

/**
 * The operational command of HU-IDENT-004, run by whoever holds the DevOps role:
 *
 * <pre>java -jar identity-app.jar --issue-service-token=svc-workflow</pre>
 *
 * It reads the same keys as the service (JWT_PRIVATE_KEY / _FILE and JWT_PUBLIC_KEY /
 * _FILE), prints the token on stdout and exits. No web server and no database start.
 */
final class ServiceTokenCommand {

    static final String OPTION = "--issue-service-token=";

    private ServiceTokenCommand() { }

    static Optional<String> subject(String[] args) {
        return Arrays.stream(args).filter(a -> a.startsWith(OPTION)).map(a -> a.substring(OPTION.length())).findFirst();
    }

    /** 0: the token is on stdout. 2: a bad subject, lifetime or key; the reason is on stderr. */
    static int run(String subject, Map<String, String> env, PrintStream out, PrintStream err) {
        try {
            RSAPrivateCrtKey privateKey = RsaKeys.readPrivate(Pem.read(env.get("JWT_PRIVATE_KEY"), env.get("JWT_PRIVATE_KEY_FILE")));
            RSAPublicKey publicKey = RsaKeys.readPublic(Pem.read(env.get("JWT_PUBLIC_KEY"), env.get("JWT_PUBLIC_KEY_FILE")));
            RsaKeys.requirePair(privateKey, publicKey);
            String days = env.getOrDefault("SERVICE_TOKEN_TTL_DAYS", "");
            Duration ttl = days.isBlank() ? ServiceTokenIssuer.DEFAULT_TTL : Duration.ofDays(Long.parseLong(days.strip()));
            Instant now = Instant.now();
            String token = new ServiceTokenIssuer(new Rs256TokenSigner(privateKey, RsaKeys.keyId(publicKey)))
                    .issue(subject, now, ttl);
            out.println(token);
            err.println("issued a service token for " + subject + ", valid until " + now.plus(ttl));
            return 0;
        } catch (IllegalArgumentException | IOException e) {   // NumberFormatException included
            err.println("issue-service-token: " + e.getMessage());
            return 2;
        }
    }
}
