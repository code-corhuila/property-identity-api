package co.edu.corhuila.property.identity.app;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** E-15 GET /jwks and HU-IDENT-004 scenario 1: Identity publishes the key that verifies its tokens. */
@SpringBootTest
@AutoConfigureMockMvc
class JwksHttpTest {

    static final KeyPair KEYS = generate();

    @Autowired
    MockMvc mvc;

    @DynamicPropertySource
    static void keys(DynamicPropertyRegistry registry) {
        registry.add("JWT_PUBLIC_KEY", () -> pem("PUBLIC", KEYS.getPublic().getEncoded()));
        registry.add("JWT_PRIVATE_KEY", () -> pem("PRIVATE", KEYS.getPrivate().getEncoded()));
    }

    @Test
    void publishesThePublicKeyWithoutAToken() throws Exception {
        String body = mvc.perform(get("/api/v1/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys.length()", is(1)))
                .andExpect(jsonPath("$.keys[0].kty", is("RSA")))
                .andExpect(jsonPath("$.keys[0].alg", is("RS256")))
                .andExpect(jsonPath("$.keys[0].use", is("sig")))
                .andReturn().getResponse().getContentAsString();

        JsonNode jwk = new ObjectMapper().readTree(body).get("keys").get(0);
        Base64.Decoder dec = Base64.getUrlDecoder();
        PublicKey rebuilt = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                new BigInteger(1, dec.decode(jwk.get("n").asText())), new BigInteger(1, dec.decode(jwk.get("e").asText()))));
        assertEquals(KEYS.getPublic(), rebuilt);
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
