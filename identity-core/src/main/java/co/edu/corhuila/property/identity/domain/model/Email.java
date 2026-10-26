package co.edu.corhuila.property.identity.domain.model;

import java.util.Locale;

/**
 * The login identifier of an account (Value Object, 02-domain/entities-and-rules.md).
 * Stored in lower case and at most 255 characters, as chk_user_account_email
 * requires, so "Ana@Example.com" and "ana@example.com" are the same account.
 */
public record Email(String value) {

    private static final int MAX_LENGTH = 255;

    public Email {
        if (value == null || value.isBlank()) {
            throw new DomainException("El email es requerido");
        }
        value = value.strip().toLowerCase(Locale.ROOT);
        int at = value.indexOf('@');
        if (at < 1 || at != value.lastIndexOf('@') || at == value.length() - 1 || value.contains(" ")) {
            throw new DomainException("El email no tiene un formato válido");
        }
        if (value.length() > MAX_LENGTH) {
            throw new DomainException("El email no puede superar " + MAX_LENGTH + " caracteres");
        }
    }
}
