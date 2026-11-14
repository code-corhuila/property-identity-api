package co.edu.corhuila.property.identity.adapter.out.security;

import co.edu.corhuila.property.identity.application.port.out.PasswordHasher;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** bcrypt, cost 12 or more (security-rules.md A02): a lower cost is refused at start. */
public class BcryptPasswordHasher implements PasswordHasher {

    public static final int MIN_COST = 12;

    private final BCryptPasswordEncoder encoder;

    public BcryptPasswordHasher(int cost) {
        if (cost < MIN_COST) {
            throw new IllegalArgumentException("PASSWORD_HASH_COST must be " + MIN_COST + " or more");
        }
        this.encoder = new BCryptPasswordEncoder(cost);
    }

    @Override
    public String hash(String password) {
        return encoder.encode(password);
    }

    @Override
    public boolean matches(String password, String hash) {
        return encoder.matches(password, hash);
    }
}
