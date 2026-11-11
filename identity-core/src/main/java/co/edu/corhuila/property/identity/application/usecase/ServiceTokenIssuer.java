package co.edu.corhuila.property.identity.application.usecase;

import co.edu.corhuila.property.identity.application.port.out.TokenSigner;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/**
 * HU-IDENT-004: the credential of property-workflow and property-worker. RS256,
 * claims sub, scope "service", iat and exp, no roles (D-C14); 30 days by default
 * (security-policy.md, Service tokens). No endpoint issues it: an operational command does.
 */
public class ServiceTokenIssuer {

    /** The only two components that call the services with their own credential. */
    public static final Set<String> SUBJECTS = Set.of("svc-workflow", "svc-worker");
    public static final Duration DEFAULT_TTL = Duration.ofDays(30);

    private final TokenSigner signer;

    public ServiceTokenIssuer(TokenSigner signer) {
        this.signer = signer;
    }

    public String issue(String subject, Instant now, Duration ttl) {
        if (!SUBJECTS.contains(subject)) {
            throw new IllegalArgumentException("the subject must be svc-workflow or svc-worker, not '" + subject + "'");
        }
        if (ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("the lifetime must be positive");
        }
        return signer.sign(TokenSigner.Claims.service(subject, now, now.plus(ttl)));
    }
}
