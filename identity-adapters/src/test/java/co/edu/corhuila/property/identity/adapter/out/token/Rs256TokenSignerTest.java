package co.edu.corhuila.property.identity.adapter.out.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.property.identity.adapter.in.http.Rs256Verifier;
import co.edu.corhuila.property.identity.application.port.out.TokenSigner.Claims;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/** What Identity signs is what every service accepts (Rs256Verifier, the same check they all run). */
class Rs256TokenSignerTest {

    static final KeyPair KEYS = generate();
    static final KeyPair OTHER = generate();
    static final Instant NOW = Instant.now();

    final Rs256TokenSigner signer = new Rs256TokenSigner(
            RsaKeys.readPrivate(pem("PRIVATE", KEYS.getPrivate().getEncoded())),
            RsaKeys.keyId((RSAPublicKey) KEYS.getPublic()));
    final Rs256Verifier verifier = new Rs256Verifier(pem("PUBLIC", KEYS.getPublic().getEncoded()));

    @Test
    void aPersonTokenCarriesSubRolesIatExpAndJti() throws Exception {
        String token = signer.sign(Claims.person("6f178b1a-9c0d-4c23-96ad-1e8da3b2ef6d", "GUEST", NOW,
                NOW.plusSeconds(3600), "jti-1"));

        JsonNode claims = verifier.verify(token, NOW);
        assertEquals("6f178b1a-9c0d-4c23-96ad-1e8da3b2ef6d", claims.get("sub").asText());
        assertEquals("GUEST", claims.get("roles").get(0).asText());
        assertEquals(1, claims.get("roles").size());
        assertEquals(NOW.getEpochSecond(), claims.get("iat").asLong());
        assertEquals(NOW.getEpochSecond() + 3600, claims.get("exp").asLong());
        assertEquals("jti-1", claims.get("jti").asText());
        assertFalse(claims.has("scope"));
    }

    @Test
    void aServiceTokenCarriesScopeServiceAndNoRoles() throws Exception {
        JsonNode claims = verifier.verify(signer.sign(Claims.service("svc-workflow", NOW, NOW.plusSeconds(60))), NOW);

        assertEquals("svc-workflow", claims.get("sub").asText());
        assertEquals("service", claims.get("scope").asText());
        assertFalse(claims.has("roles"));
    }

    @Test
    void theHeaderIsRs256AndNamesTheKey() throws Exception {
        String token = signer.sign(Claims.service("svc-worker", NOW, NOW.plusSeconds(60)));
        JsonNode header = new ObjectMapper().readTree(Base64.getUrlDecoder().decode(token.split("\\.")[0]));

        assertEquals("RS256", header.get("alg").asText());
        assertEquals(RsaKeys.keyId((RSAPublicKey) KEYS.getPublic()), header.get("kid").asText());
    }

    @Test
    void anotherKeyDoesNotVerifyIt() {
        Rs256Verifier other = new Rs256Verifier(pem("PUBLIC", OTHER.getPublic().getEncoded()));
        String token = signer.sign(Claims.service("svc-worker", NOW, NOW.plusSeconds(60)));

        assertThrows(Rs256Verifier.InvalidTokenException.class, () -> other.verify(token, NOW));
    }

    @Test
    void twoKeysThatAreNotOnePairAreRejectedAtStart() {
        var privateKey = RsaKeys.readPrivate(pem("PRIVATE", KEYS.getPrivate().getEncoded()));

        RsaKeys.requirePair(privateKey, (RSAPublicKey) KEYS.getPublic());
        assertThrows(IllegalArgumentException.class, () -> RsaKeys.requirePair(privateKey, (RSAPublicKey) OTHER.getPublic()));
    }

    @Test
    void onlyPemKeysAreRead() {
        assertThrows(IllegalArgumentException.class, () -> RsaKeys.readPrivate("not a key"));
        assertThrows(IllegalArgumentException.class, () -> RsaKeys.readPrivate(pem("PUBLIC", KEYS.getPublic().getEncoded())));
        assertThrows(IllegalArgumentException.class, () -> RsaKeys.readPublic(""));
    }

    @Test
    void theKeyIdIsStableAndDiffersBetweenKeys() {
        String kid = RsaKeys.keyId((RSAPublicKey) KEYS.getPublic());

        assertEquals(kid, RsaKeys.keyId(RsaKeys.readPublic(pem("PUBLIC", KEYS.getPublic().getEncoded()))));
        assertFalse(kid.equals(RsaKeys.keyId((RSAPublicKey) OTHER.getPublic())));
        assertTrue(kid.matches("[A-Za-z0-9_-]{43}"));
    }

    static String pem(String kind, byte[] der) {
        return "-----BEGIN " + kind + " KEY-----\n" + Base64.getMimeEncoder().encodeToString(der)
                + "\n-----END " + kind + " KEY-----\n";
    }

    static KeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
