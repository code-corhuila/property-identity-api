package co.edu.corhuila.property.identity.application.port.out;

import java.time.Instant;
import java.util.List;

/**
 * Signs a JWT with Identity's private key, RS256 only (security-policy.md). Identity
 * is the only holder of that key (ADR-011, rule 4).
 */
public interface TokenSigner {

    /**
     * The claims of a token. A person's token carries roles and a jti; a service
     * token carries scope "service" and no roles (D-C14). Null fields are left out.
     */
    record Claims(String subject, List<String> roles, String scope, Instant issuedAt, Instant expiresAt, String id) {

        public static Claims person(String subject, String role, Instant issuedAt, Instant expiresAt, String id) {
            return new Claims(subject, List.of(role), null, issuedAt, expiresAt, id);
        }

        public static Claims service(String subject, Instant issuedAt, Instant expiresAt) {
            return new Claims(subject, null, "service", issuedAt, expiresAt, null);
        }
    }

    String sign(Claims claims);
}
