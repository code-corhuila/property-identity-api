package co.edu.corhuila.property.identity.domain.model;

import java.util.List;

/**
 * The authorization role of an account (00-governance/security-policy.md,
 * 07-api/guidelines.md D-C9). One role per account; no ad hoc roles.
 */
public enum Role {
    GUEST,
    HOST,
    ADMIN;

    /**
     * security-policy.md, Authorization. A HOST has what a GUEST has; an ADMIN has
     * the same names, and its reads reach every user. A person never has
     * reservas:create or pagos:create: those belong to the service credential (D-C12).
     */
    private static final List<String> PERSON_PERMISSIONS = List.of("propiedades:read", "sagas:create",
            "sagas:read", "reservas:read", "reservas:cancel", "pagos:read", "preferencias:read", "preferencias:update");

    public List<String> permissions() {
        return PERSON_PERMISSIONS;
    }
}
