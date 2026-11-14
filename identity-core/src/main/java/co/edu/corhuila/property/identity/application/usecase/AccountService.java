package co.edu.corhuila.property.identity.application.usecase;

import co.edu.corhuila.property.identity.application.port.in.AccountUseCases.GetMe;
import co.edu.corhuila.property.identity.application.port.in.AccountUseCases.Register;
import co.edu.corhuila.property.identity.application.port.in.AccountUseCases.RegisterCommand;
import co.edu.corhuila.property.identity.application.port.in.AccountUseCases.Registration;
import co.edu.corhuila.property.identity.application.port.in.AccountUseCases.UpgradeToHost;
import co.edu.corhuila.property.identity.application.port.in.Caller;
import co.edu.corhuila.property.identity.application.port.in.NotAuthenticatedException;
import co.edu.corhuila.property.identity.application.port.out.PasswordHasher;
import co.edu.corhuila.property.identity.application.port.out.UserAccountRepository;
import co.edu.corhuila.property.identity.domain.model.Email;
import co.edu.corhuila.property.identity.domain.model.InvalidStatusTransitionException;
import co.edu.corhuila.property.identity.domain.model.Role;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import java.lang.System.Logger.Level;
import java.time.Clock;

/** E-10, E-25 and E-14. It orchestrates; the rules of an account live in UserAccount. */
public class AccountService implements Register, GetMe, UpgradeToHost {

    private static final System.Logger SECURITY = System.getLogger("security");

    private final UserAccountRepository accounts;
    private final PasswordHasher hasher;
    private final SessionIssuer sessions;
    private final Clock clock;

    public AccountService(UserAccountRepository accounts, PasswordHasher hasher, SessionIssuer sessions, Clock clock) {
        this.accounts = accounts;
        this.hasher = hasher;
        this.sessions = sessions;
        this.clock = clock;
    }

    /** HU-IDENT-001: a new account is a GUEST and gets its first session at once. */
    @Override
    public Registration register(RegisterCommand command) {
        UserAccount account = UserAccount.register(new Email(command.email()), hasher.hash(command.password()),
                command.name());
        UserAccountRepository.RegisterResult stored = accounts.register(account, command.idempotencyKey());
        if (!stored.created()) {
            return new Registration(stored.account(), null, false);
        }
        return new Registration(stored.account(), sessions.open(stored.account(), clock.instant()), true);
    }

    /** E-25: the account of the person of the token; a service credential gets 403 (D-C14). */
    @Override
    public UserAccount getMe(Caller caller) {
        return accounts.findById(caller.requirePerson())
                .orElseThrow(() -> new NotAuthenticatedException("the account of the token does not exist"));
    }

    /**
     * HU-IDENT-003: a GUEST becomes a HOST; tokens issued from then on carry HOST.
     * Any other role is 422 INVALID_STATUS_TRANSITION, also when a concurrent
     * request upgraded it first.
     */
    @Override
    public UserAccount upgradeToHost(Caller caller) {
        UserAccount account = getMe(caller);
        account.upgradeToHost();
        if (!accounts.changeRole(account.getId(), Role.GUEST, Role.HOST, clock.instant())) {
            throw new InvalidStatusTransitionException("only a GUEST account can become a HOST");
        }
        SECURITY.log(Level.INFO, "action=auth.role.changed result=SUCCESS userId={0} from=GUEST to=HOST", account.getId());
        return account;
    }
}
