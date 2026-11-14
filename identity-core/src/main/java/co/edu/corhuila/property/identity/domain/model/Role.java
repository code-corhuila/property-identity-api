package co.edu.corhuila.property.identity.domain.model;

/**
 * The authorization role of an account (00-governance/security-policy.md,
 * 07-api/guidelines.md D-C9). One role per account; no ad hoc roles.
 */
public enum Role {
    GUEST,
    HOST,
    ADMIN
}
