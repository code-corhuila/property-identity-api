package co.edu.corhuila.property.identity.adapter.in.http;

import co.edu.corhuila.property.identity.application.port.in.AuthSession;
import co.edu.corhuila.property.identity.application.port.in.Caller;
import co.edu.corhuila.property.identity.domain.model.UserAccount;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

/** The public shapes of identity-service.yaml. The domain entity is never serialized directly. */
final class AccountViews {

    private AccountViews() { }

    /** UserSummary: one role (an array, like the claim) and the permissions of that role. */
    record UserSummary(String id, String email, String name, List<String> roles, List<String> permissions) {
        static UserSummary of(UserAccount a) {
            return new UserSummary(a.getId().toString(), a.getEmail().value(), a.getFullName(),
                    List.of(a.getRole().name()), a.getRole().permissions());
        }
    }

    /** UserContact (E-26): what notification-service needs to write to a guest, nothing more. */
    record UserContact(String id, String email, String name) {
        static UserContact of(UserAccount a) {
            return new UserContact(a.getId().toString(), a.getEmail().value(), a.getFullName());
        }
    }

    record AuthResponse(String accessToken, String refreshToken, long expiresIn, UserSummary user) {
        static AuthResponse of(AuthSession s) {
            return new AuthResponse(s.accessToken(), s.refreshToken(), s.expiresIn(), UserSummary.of(s.account()));
        }
    }

    /** The caller of a protected route, from the claims AuthFilter verified. */
    static Caller caller(HttpServletRequest request) {
        JsonNode claims = (JsonNode) request.getAttribute(AuthFilter.CLAIMS_ATTRIBUTE);
        List<String> roles = new ArrayList<>();
        claims.path("roles").forEach(r -> roles.add(r.asText()));
        return new Caller(claims.path("sub").asText(), roles, "service".equals(claims.path("scope").asText()));
    }
}
