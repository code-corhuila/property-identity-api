package co.edu.corhuila.property.identity.adapter.in.http;

import co.edu.corhuila.property.identity.adapter.in.http.AccountViews.AuthResponse;
import co.edu.corhuila.property.identity.adapter.in.http.ApiError.FieldError;
import co.edu.corhuila.property.identity.adapter.in.http.ApiError.ValidationException;
import co.edu.corhuila.property.identity.application.port.in.AuthSession;
import co.edu.corhuila.property.identity.application.port.in.NotAuthenticatedException;
import co.edu.corhuila.property.identity.application.port.in.SessionUseCases;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** E-11 POST /login, E-12 POST /refresh and E-13 POST /logout. */
@RestController
@RequestMapping("/api/v1")
public class SessionController {

    /** security-policy.md, Audit: who, from where, what and the result. Never the password or a token. */
    private static final Logger SECURITY = LoggerFactory.getLogger("security");

    public record LoginRequest(String email, String password) { }

    public record RefreshRequest(String refreshToken) { }

    public record LogoutRequest(String refreshToken, Boolean allDevices) { }

    private final SessionUseCases.Login login;
    private final SessionUseCases.Refresh refresh;
    private final SessionUseCases.Logout logout;

    public SessionController(SessionUseCases.Login login, SessionUseCases.Refresh refresh, SessionUseCases.Logout logout) {
        this.login = login;
        this.refresh = refresh;
        this.logout = logout;
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest body, HttpServletRequest request) {
        List<FieldError> problems = new ArrayList<>();
        if (body.email() == null || !AccountController.EMAIL.matcher(body.email().strip()).matches()) {
            problems.add(new FieldError("email", "an e-mail address is required"));
        }
        if (body.password() == null || body.password().isEmpty()) {
            problems.add(new FieldError("password", "required"));
        }
        if (!problems.isEmpty()) {
            throw new ValidationException("the request has invalid fields", problems);
        }
        try {
            AuthSession session = login.login(body.email(), body.password());
            SECURITY.info("action=auth.login.success result=SUCCESS userId={} sourceIp={}",
                    session.account().getId(), sourceIp(request));
            return AuthResponse.of(session);
        } catch (NotAuthenticatedException e) {
            // The user is its sub, or ANONYMOUS when the e-mail has no account: never the e-mail itself.
            SECURITY.warn("action=auth.login.failure result=FAILURE userId={} sourceIp={} userAgent={}",
                    e.accountId().map(UUID::toString).orElse("ANONYMOUS"), sourceIp(request),
                    request.getHeader("User-Agent"));
            throw e;
        }
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody RefreshRequest body) {
        if (body.refreshToken() == null || body.refreshToken().isBlank()) {
            throw new ValidationException("the request has invalid fields",
                    List.of(new FieldError("refreshToken", "required")));
        }
        return AuthResponse.of(refresh.refresh(body.refreshToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequest body, HttpServletRequest request) {
        boolean all = Boolean.TRUE.equals(body.allDevices());
        if (!all && (body.refreshToken() == null || body.refreshToken().isBlank())) {
            throw new ValidationException("send refreshToken, allDevices: true, or both",
                    List.of(new FieldError("refreshToken", "required unless allDevices is true")));
        }
        logout.logout(AccountViews.caller(request), body.refreshToken(), all);
        return ResponseEntity.noContent().build();
    }

    /** The gateway forwards the client address in X-Forwarded-For; the first one is the client's. */
    private static String sourceIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded == null || forwarded.isBlank() ? request.getRemoteAddr() : forwarded.split(",")[0].strip();
    }
}
