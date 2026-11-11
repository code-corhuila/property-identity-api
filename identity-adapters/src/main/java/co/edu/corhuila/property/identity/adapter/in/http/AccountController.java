package co.edu.corhuila.property.identity.adapter.in.http;

import co.edu.corhuila.property.identity.adapter.in.http.AccountViews.AuthResponse;
import co.edu.corhuila.property.identity.adapter.in.http.AccountViews.UserContact;
import co.edu.corhuila.property.identity.adapter.in.http.AccountViews.UserSummary;
import co.edu.corhuila.property.identity.adapter.in.http.ApiError.FieldError;
import co.edu.corhuila.property.identity.adapter.in.http.ApiError.ValidationException;
import co.edu.corhuila.property.identity.application.port.in.AccountUseCases;
import co.edu.corhuila.property.identity.application.port.in.AccountUseCases.RegisterCommand;
import co.edu.corhuila.property.identity.application.port.in.AccountUseCases.Registration;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * E-10 POST /register, E-25 GET /users/me, E-14 POST /users/me/upgrade-to-host and E-26
 * GET /users/{id}/contact. Validates the SHAPE of the input
 * (identity-service.yaml) and holds no business rule.
 */
@RestController
@RequestMapping("/api/v1")
public class AccountController {

    static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    static final Pattern UPPERCASE = Pattern.compile("\\p{Lu}");
    static final Pattern DIGIT = Pattern.compile("\\d");

    public record RegisterRequest(String email, String password, String name) { }

    private final AccountUseCases.Register register;
    private final AccountUseCases.GetMe getMe;
    private final AccountUseCases.UpgradeToHost upgrade;
    private final AccountUseCases.GetContact contact;

    public AccountController(AccountUseCases.Register register, AccountUseCases.GetMe getMe,
                             AccountUseCases.UpgradeToHost upgrade, AccountUseCases.GetContact contact) {
        this.register = register;
        this.getMe = getMe;
        this.upgrade = upgrade;
        this.contact = contact;
    }

    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody RegisterRequest body,
                                           @RequestHeader(name = "Idempotency-Key", required = false) String key) {
        List<FieldError> problems = new ArrayList<>();
        if (body.email() == null || body.email().length() > 255 || !EMAIL.matcher(body.email().strip()).matches()) {
            problems.add(new FieldError("email", "must be an e-mail address of at most 255 characters"));
        }
        String password = body.password();
        if (password == null || password.length() < 8 || password.length() > 100
                || !UPPERCASE.matcher(password).find() || !DIGIT.matcher(password).find()) {
            problems.add(new FieldError("password", "8 to 100 characters, with an uppercase letter and a digit"));
        }
        if (body.name() == null || body.name().isBlank() || body.name().strip().length() > 100) {
            problems.add(new FieldError("name", "required, 1 to 100 characters"));
        }
        requireKey(key, problems);
        if (!problems.isEmpty()) {
            throw new ValidationException("the request has invalid fields", problems);
        }
        Registration result = register.register(new RegisterCommand(body.email(), password, body.name(), key));
        if (!result.created()) {
            return ResponseEntity.ok(UserSummary.of(result.account()));   // a retry: no tokens
        }
        return ResponseEntity.status(HttpStatus.CREATED).header("Location", "/api/v1/users/me")
                .body(AuthResponse.of(result.session()));
    }

    @GetMapping("/users/me")
    public UserSummary me(HttpServletRequest request) {
        return UserSummary.of(getMe.getMe(AccountViews.caller(request)));
    }

    @PostMapping("/users/me/upgrade-to-host")
    public UserSummary upgradeToHost(HttpServletRequest request) {
        return UserSummary.of(upgrade.upgradeToHost(AccountViews.caller(request)));
    }

    @GetMapping("/users/{id}/contact")
    public UserContact contact(@PathVariable("id") String id, HttpServletRequest request) {
        UUID accountId;
        try {
            accountId = UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            throw new ValidationException("the id is not a UUID", List.of(new FieldError("id", "must be a UUID")));
        }
        return UserContact.of(contact.getContact(AccountViews.caller(request), accountId));
    }

    static void requireKey(String key, List<FieldError> problems) {
        if (key == null || key.length() < 8 || key.length() > 128) {
            problems.add(new FieldError("Idempotency-Key", "header required, 8 to 128 characters"));
        }
    }
}
