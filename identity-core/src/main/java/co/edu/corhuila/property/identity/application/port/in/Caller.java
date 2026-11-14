package co.edu.corhuila.property.identity.application.port.in;

import java.util.List;
import java.util.UUID;

/**
 * Who calls, as the verified token says: a person (claim roles) or a service
 * (claim scope: service, D-C14). The inbound adapter builds it; the use case decides
 * the permission (security-rules.md A01: in the use case, never in the controller).
 */
public record Caller(String subject, List<String> roles, boolean service) {

    public Caller {
        roles = roles == null ? List.of() : List.copyOf(roles);
    }

    /**
     * The account of a person. A service credential, or a token with no role, has no
     * permission here (403); a person's token whose subject is not an account id is
     * not a valid credential (401).
     */
    public UUID requirePerson() {
        if (service || roles.isEmpty()) {
            throw new AccessDeniedException("this credential is not allowed to perform the operation");
        }
        try {
            return UUID.fromString(subject);
        } catch (IllegalArgumentException e) {
            throw new NotAuthenticatedException("the token does not name an account");
        }
    }

    /** Only the service credential of that subject (D-C14); a person or another service gets 403. */
    public void requireService(String allowedSubject) {
        if (!service || !allowedSubject.equals(subject)) {
            throw new AccessDeniedException("this credential is not allowed to perform the operation");
        }
    }
}
