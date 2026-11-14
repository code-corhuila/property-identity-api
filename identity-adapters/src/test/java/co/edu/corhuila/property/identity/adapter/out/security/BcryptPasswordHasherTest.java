package co.edu.corhuila.property.identity.adapter.out.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class BcryptPasswordHasherTest {

    final BcryptPasswordHasher hasher = new BcryptPasswordHasher(12);

    @Test
    void hashesWithBcryptCost12AndNeverKeepsThePassword() {
        String hash = hasher.hash("SecurePass123!");

        assertTrue(hash.startsWith("$2a$12$"), hash);
        assertFalse(hash.contains("SecurePass123!"));
        assertNotEquals(hash, hasher.hash("SecurePass123!"), "a new salt every time");
        assertTrue(hasher.matches("SecurePass123!", hash));
        assertFalse(hasher.matches("securepass123!", hash));
    }

    @Test
    void aCostBelow12IsRefused() {
        assertThrows(IllegalArgumentException.class, () -> new BcryptPasswordHasher(10));
    }
}
