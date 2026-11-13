package co.edu.corhuila.property.identity.domain.model;

/** The account is not in a state that allows the transition (07-api, E-14). */
public class InvalidStatusTransitionException extends DomainException {
    public InvalidStatusTransitionException(String message) {
        super(message);
    }
}
