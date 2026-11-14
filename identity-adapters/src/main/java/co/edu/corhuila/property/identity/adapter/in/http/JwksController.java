package co.edu.corhuila.property.identity.adapter.in.http;

import co.edu.corhuila.property.identity.adapter.out.token.RsaKeys;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * E-15 GET /jwks, public: the published copy of the public key (RFC 7517). No
 * service calls it while serving a request; each one receives the key as
 * JWT_PUBLIC_KEY, and this is where an environment's key is taken from.
 */
@RestController
public class JwksController {

    private final Map<String, Object> jwks;

    public JwksController(RSAPublicKey publicKey) {
        Map<String, Object> jwk = Map.of(
                "kty", "RSA",
                "use", "sig",
                "alg", "RS256",
                "kid", RsaKeys.keyId(publicKey),
                "n", RsaKeys.base64Url(publicKey.getModulus().toByteArray()),
                "e", RsaKeys.base64Url(publicKey.getPublicExponent().toByteArray()));
        this.jwks = Map.of("keys", List.of(jwk));
    }

    @GetMapping("/api/v1/jwks")
    public Map<String, Object> jwks() {
        return jwks;
    }
}
