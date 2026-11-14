package co.edu.corhuila.property.identity.application.port.in;

/**
 * The credentials do not identify an active account or session: 401 UNAUTHORIZED.
 * Wrong e-mail, wrong password and a locked account share one message (A07).
 */
public class NotAuthenticatedException extends RuntimeException {
    public NotAuthenticatedException(String message) {
        super(message);
    }
}
