package co.edu.corhuila.property.identity.application.port.in;

import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.util.UUID;

/** What the service offers about accounts. Inbound adapters depend on these interfaces only. */
public final class AccountUseCases {

    private AccountUseCases() { }

    /** The shape was already validated by the inbound adapter (E-10). */
    public record RegisterCommand(String email, String password, String name, String idempotencyKey) { }

    /**
     * created=true: the account and its first session. created=false: the key was
     * already used, the account it created and no session (a repeated key never
     * opens one, E-10).
     */
    public record Registration(UserAccount account, AuthSession session, boolean created) { }

    public interface Register {
        Registration register(RegisterCommand command);
    }

    public interface GetMe {
        UserAccount getMe(Caller caller);
    }

    public interface UpgradeToHost {
        UserAccount upgradeToHost(Caller caller);
    }

    /** E-26: the e-mail and name of an account, for notification-service only (GAP-017). */
    public interface GetContact {
        UserAccount getContact(Caller caller, UUID accountId);
    }
}
