package co.edu.corhuila.property.identity.application.port.in;

/** No account has that id (404 NOT_FOUND). */
public class AccountNotFoundException extends RuntimeException {

    public AccountNotFoundException(String message) {
        super(message);
    }
}
