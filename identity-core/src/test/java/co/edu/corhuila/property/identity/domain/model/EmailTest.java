package co.edu.corhuila.property.identity.domain.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EmailTest {

    @Test
    void isStoredInLowerCase() {
        assertEquals("ana@example.com", new Email(" Ana@Example.COM ").value());
        assertEquals(new Email("ana@example.com"), new Email("ANA@example.com"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "ana", "@example.com", "ana@", "ana@@example.com", "a na@example.com"})
    void rejectsWhatIsNotAnEmail(String value) {
        assertThrows(DomainException.class, () -> new Email(value));
    }

    @Test
    void rejectsMoreThan255Characters() {
        assertThrows(DomainException.class, () -> new Email("a".repeat(250) + "@example.com"));
    }
}
