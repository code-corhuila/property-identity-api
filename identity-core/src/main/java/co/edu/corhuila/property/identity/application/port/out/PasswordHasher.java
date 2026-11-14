package co.edu.corhuila.property.identity.application.port.out;

/** bcrypt with cost 12 or more (security-rules.md A02). The password is never stored or logged. */
public interface PasswordHasher {

    String hash(String password);

    boolean matches(String password, String hash);
}
