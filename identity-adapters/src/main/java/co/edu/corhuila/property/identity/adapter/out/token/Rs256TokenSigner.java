package co.edu.corhuila.property.identity.adapter.out.token;

import co.edu.corhuila.property.identity.application.port.out.TokenSigner;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Signs with RS256 (RSASSA-PKCS1-v1_5 with SHA-256), the only algorithm of the
 * project (security-policy.md). The header names the key (kid) that /jwks publishes.
 */
public class Rs256TokenSigner implements TokenSigner {

    private final RSAPrivateKey key;
    private final String encodedHeader;
    private final ObjectMapper json = new ObjectMapper();

    public Rs256TokenSigner(RSAPrivateKey key, String keyId) {
        this.key = key;
        this.encodedHeader = encode(("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"" + keyId + "\"}")
                .getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String sign(Claims claims) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", claims.subject());
        if (claims.roles() != null) {
            payload.put("roles", claims.roles());
        }
        if (claims.scope() != null) {
            payload.put("scope", claims.scope());
        }
        payload.put("iat", claims.issuedAt().getEpochSecond());
        payload.put("exp", claims.expiresAt().getEpochSecond());
        if (claims.id() != null) {
            payload.put("jti", claims.id());
        }
        try {
            String signingInput = encodedHeader + "." + encode(json.writeValueAsBytes(payload));
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(key);
            rsa.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return signingInput + "." + encode(rsa.sign());
        } catch (JsonProcessingException | GeneralSecurityException e) {
            throw new IllegalStateException("the token could not be signed", e);
        }
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
