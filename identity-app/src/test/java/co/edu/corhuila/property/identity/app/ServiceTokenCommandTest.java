package co.edu.corhuila.property.identity.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.corhuila.property.identity.adapter.in.http.Rs256Verifier;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** HU-IDENT-004 scenario 1: the operational command issues the token of the workflow and the worker. */
class ServiceTokenCommandTest {

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final Map<String, String> env = new HashMap<>(Map.of(
            "JWT_PRIVATE_KEY", oneLine(TestKeys.pem("PRIVATE", TestKeys.KEYS.getPrivate().getEncoded())),
            "JWT_PUBLIC_KEY", oneLine(TestKeys.pem("PUBLIC", TestKeys.KEYS.getPublic().getEncoded()))));

    int run(String subject) {
        return ServiceTokenCommand.run(subject, env, new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    JsonNode claimsOfPrintedToken() throws Exception {
        String token = out.toString(StandardCharsets.UTF_8).strip();
        return new Rs256Verifier(TestKeys.pem("PUBLIC", TestKeys.KEYS.getPublic().getEncoded())).verify(token, Instant.now());
    }

    @Test
    void issuesAnRs256TokenWithScopeServiceNoRolesAndThirtyDays() throws Exception {
        assertEquals(0, run("svc-workflow"));

        JsonNode claims = claimsOfPrintedToken();
        assertEquals("svc-workflow", claims.get("sub").asText());
        assertEquals("service", claims.get("scope").asText());
        assertFalse(claims.has("roles"));
        assertEquals(30L * 24 * 3600, claims.get("exp").asLong() - claims.get("iat").asLong());
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("valid until"));
    }

    @Test
    void theLifetimeAndTheKeyFilesComeFromTheEnvironment(@TempDir Path dir) throws Exception {
        Path privateFile = Files.writeString(dir.resolve("jwt-private.pem"),
                TestKeys.pem("PRIVATE", TestKeys.KEYS.getPrivate().getEncoded()));
        env.remove("JWT_PRIVATE_KEY");
        env.put("JWT_PRIVATE_KEY_FILE", privateFile.toString());
        env.put("SERVICE_TOKEN_TTL_DAYS", "7");

        assertEquals(0, run("svc-worker"));
        JsonNode claims = claimsOfPrintedToken();
        assertEquals("svc-worker", claims.get("sub").asText());
        assertEquals(7L * 24 * 3600, claims.get("exp").asLong() - claims.get("iat").asLong());
    }

    @Test
    void onlyTheWorkflowAndTheWorkerGetOne() {
        assertEquals(2, run("svc-anyone"));
        assertEquals(2, run("6f178b1a-9c0d-4c23-96ad-1e8da3b2ef6d"));
        assertEquals("", out.toString(StandardCharsets.UTF_8));
    }

    @Test
    void withoutKeysOrWithKeysThatAreNotOnePairNothingIsIssued() throws Exception {
        env.put("JWT_PUBLIC_KEY", TestKeys.pem("PUBLIC", otherKeyPair().getPublic().getEncoded()));
        assertEquals(2, run("svc-workflow"));

        env.remove("JWT_PRIVATE_KEY");
        assertEquals(2, run("svc-workflow"));
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("issue-service-token:"));
        assertEquals("", out.toString(StandardCharsets.UTF_8));
    }

    @Test
    void theOptionIsReadFromTheArguments() {
        assertEquals(Optional.of("svc-workflow"),
                ServiceTokenCommand.subject(new String[] {"--debug", "--issue-service-token=svc-workflow"}));
        assertTrue(ServiceTokenCommand.subject(new String[] {"--server.port=3004"}).isEmpty());
    }

    /** How a .env file holds a PEM: one line with literal \n. */
    static String oneLine(String pem) {
        return pem.replace("\n", "\\n");
    }

    static KeyPair otherKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
