package co.edu.corhuila.property.identity.application.port.out;

import co.edu.corhuila.property.identity.domain.model.DomainException;

/** E-10: the e-mail already has an account (422 BUSINESS_RULE_VIOLATION). */
public class EmailAlreadyRegisteredException extends DomainException {
    public EmailAlreadyRegisteredException() {
        super("the e-mail is already registered");
    }
}
