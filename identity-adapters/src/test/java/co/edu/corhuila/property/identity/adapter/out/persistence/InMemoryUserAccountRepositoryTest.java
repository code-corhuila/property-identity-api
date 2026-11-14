package co.edu.corhuila.property.identity.adapter.out.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.property.identity.application.port.out.EmailAlreadyRegisteredException;
import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** The in-memory twin keeps the contract of the port, as the JDBC adapter does. */
class InMemoryUserAccountRepositoryTest {

    final InMemoryUserAccountRepository repository = new InMemoryUserAccountRepository();

    static UserAccount account(String email) {
        return UserAccount.register(new Email(email), "$2a$12$hash", "Ana Pérez");
    }

    @Test
    void storesAndFindsByIdAndByEmail() {
        UserAccount ana = account("ana@example.com");
        assertTrue(repository.register(ana, "key-00001").created());

        assertEquals(ana.getId(), repository.findById(ana.getId()).orElseThrow().getId());
        assertEquals(ana.getId(), repository.findByEmail(new Email("ANA@example.com")).orElseThrow().getId());
    }

    @Test
    void aRepeatedKeyReturnsTheFirstAccount() {
        UserAccount first = account("ana@example.com");
        repository.register(first, "key-00001");

        var retry = repository.register(account("otra@example.com"), "key-00001");

        assertFalse(retry.created());
        assertEquals(first.getId(), retry.account().getId());
        assertTrue(repository.findByEmail(new Email("otra@example.com")).isEmpty());
    }

    @Test
    void anEmailAlreadyRegisteredIsRejected() {
        repository.register(account("ana@example.com"), "key-00001");

        assertThrows(EmailAlreadyRegisteredException.class,
                () -> repository.register(account("ana@example.com"), "key-00002"));
    }

    @Test
    void countsFailuresAndLocksOnTheFifth() {
        UserAccount ana = account("ana@example.com");
        repository.register(ana, "key-00001");
        Instant now = Instant.parse("2026-11-08T10:00:00Z");

        for (int i = 0; i < UserAccount.MAX_FAILED_LOGINS; i++) {
            repository.recordFailedLogin(ana.getId(), now);
        }
        assertTrue(repository.findById(ana.getId()).orElseThrow().isLocked(now.plusSeconds(60)));

        repository.recordSuccessfulLogin(ana.getId(), now);
        assertEquals(0, repository.findById(ana.getId()).orElseThrow().getFailedLogins());
    }
}
