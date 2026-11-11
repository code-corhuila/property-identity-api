package co.edu.corhuila.property.identity.application.port.in;

import co.edu.corhuila.property.identity.domain.model.UserAccount;

/**
 * What a login, a registration or a renewal gives a person (AuthResponse): an access
 * token, the opaque refresh token in clear (the only time it exists in clear), and the
 * seconds until the access token expires.
 */
public record AuthSession(String accessToken, String refreshToken, long expiresIn, UserAccount account) { }
