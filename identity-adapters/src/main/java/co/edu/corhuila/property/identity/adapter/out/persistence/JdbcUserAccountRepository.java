package co.edu.corhuila.property.identity.adapter.out.persistence;

import co.edu.corhuila.property.identity.application.port.out.EmailAlreadyRegisteredException;
import co.edu.corhuila.property.identity.application.port.out.UserAccountRepository;
import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.Role;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Reads and writes the schema owned by property-identity-db, as identity_app. It
 * knows the column names; the domain does not (models.md, naming note).
 */
public class JdbcUserAccountRepository implements UserAccountRepository {

    private static final String COLUMNS =
            "a.id, a.email, a.password_hash, a.full_name, a.role, a.failed_logins, a.locked_until, a.created_at, a.updated_at";

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;

    public JdbcUserAccountRepository(JdbcTemplate jdbc, TransactionTemplate tx) {
        this.jdbc = jdbc;
        this.tx = tx;
    }

    @Override
    public RegisterResult register(UserAccount account, String idempotencyKey) {
        RegisterResult result = tx.execute(status -> {
            Optional<UserAccount> first = findByKey(idempotencyKey);
            if (first.isPresent()) {
                return new RegisterResult(first.get(), false);
            }
            try {
                jdbc.update("INSERT INTO identity.user_account (id, email, password_hash, full_name, role, "
                                + "failed_logins, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
                        account.getId(), account.getEmail().value(), account.getPasswordHash(), account.getFullName(),
                        account.getRole().name(), utc(account.getCreatedAt()), utc(account.getUpdatedAt()));
            } catch (DuplicateKeyException e) {
                status.setRollbackOnly();
                return null;
            }
            int inserted = jdbc.update("INSERT INTO identity.idempotency_key (key, user_id, created_at) VALUES (?, ?, ?) "
                    + "ON CONFLICT (key) DO NOTHING", idempotencyKey, account.getId(), utc(account.getCreatedAt()));
            if (inserted == 0) {
                status.setRollbackOnly();
                return null;
            }
            return new RegisterResult(account, true);
        });
        if (result != null) {
            return result;
        }
        // Rolled back: either a request with the same key won the race (its account is
        // returned), or the e-mail belongs to another account.
        return findByKey(idempotencyKey).map(first -> new RegisterResult(first, false))
                .orElseThrow(EmailAlreadyRegisteredException::new);
    }

    @Override
    public Optional<UserAccount> findById(UUID id) {
        return jdbc.query("SELECT " + COLUMNS + " FROM identity.user_account a WHERE a.id = ? AND a.deleted_at IS NULL",
                (rs, n) -> map(rs), id).stream().findFirst();
    }

    @Override
    public Optional<UserAccount> findByEmail(Email email) {
        return jdbc.query("SELECT " + COLUMNS + " FROM identity.user_account a WHERE a.email = ? AND a.deleted_at IS NULL",
                (rs, n) -> map(rs), email.value()).stream().findFirst();
    }

    @Override
    public void recordFailedLogin(UUID id, Instant now) {
        // The SET expressions read the row as it was before this UPDATE, so the
        // counter and the lock are decided on the same value.
        jdbc.update("UPDATE identity.user_account"
                        + " SET failed_logins = CASE WHEN failed_logins + 1 >= ? THEN 0 ELSE failed_logins + 1 END,"
                        + "     locked_until = CASE WHEN failed_logins + 1 >= ? THEN ? ELSE locked_until END,"
                        + "     updated_at = ?"
                        + " WHERE id = ?",
                UserAccount.MAX_FAILED_LOGINS, UserAccount.MAX_FAILED_LOGINS,
                utc(now.plus(UserAccount.LOCK_DURATION)), utc(now), id);
    }

    @Override
    public void recordSuccessfulLogin(UUID id, Instant now) {
        jdbc.update("UPDATE identity.user_account SET failed_logins = 0, updated_at = ? WHERE id = ?", utc(now), id);
    }

    @Override
    public boolean changeRole(UUID id, Role from, Role to, Instant now) {
        return jdbc.update("UPDATE identity.user_account SET role = ?, updated_at = ? WHERE id = ? AND role = ?",
                to.name(), utc(now), id, from.name()) == 1;
    }

    private Optional<UserAccount> findByKey(String key) {
        return jdbc.query("SELECT " + COLUMNS + " FROM identity.idempotency_key k"
                + " JOIN identity.user_account a ON a.id = k.user_id WHERE k.key = ?", (rs, n) -> map(rs), key)
                .stream().findFirst();
    }

    private static UserAccount map(ResultSet rs) throws SQLException {
        OffsetDateTime locked = rs.getObject("locked_until", OffsetDateTime.class);
        return UserAccount.restore(rs.getObject("id", UUID.class), new Email(rs.getString("email")),
                rs.getString("password_hash"), rs.getString("full_name"), Role.valueOf(rs.getString("role")),
                rs.getInt("failed_logins"), locked == null ? null : locked.toInstant(),
                rs.getObject("created_at", OffsetDateTime.class).toInstant(),
                rs.getObject("updated_at", OffsetDateTime.class).toInstant());
    }

    static OffsetDateTime utc(Instant instant) {
        return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
    }
}
