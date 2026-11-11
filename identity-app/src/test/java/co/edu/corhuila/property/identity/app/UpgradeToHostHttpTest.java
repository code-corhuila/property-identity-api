package co.edu.corhuila.property.identity.app;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** HU-IDENT-003 over HTTP (E-14). */
@SpringBootTest
@AutoConfigureMockMvc
class UpgradeToHostHttpTest {

    static final ObjectMapper JSON = new ObjectMapper();
    static final String UPGRADE = "/api/v1/users/me/upgrade-to-host";

    @Autowired
    MockMvc mvc;

    @DynamicPropertySource
    static void keys(DynamicPropertyRegistry registry) {
        TestKeys.register(registry);
    }

    JsonNode registerAndLogin(String email) throws Exception {
        String credentials = "\"email\":\"" + email + "\",\"password\":\"SecurePass123!\"";
        mvc.perform(post("/api/v1/register").header("Idempotency-Key", "reg-" + UUID.randomUUID())
                .contentType(MediaType.APPLICATION_JSON).content("{" + credentials + ",\"name\":\"Ana\"}"));
        return login(credentials);
    }

    JsonNode login(String credentials) throws Exception {
        return JSON.readTree(mvc.perform(post("/api/v1/login").contentType(MediaType.APPLICATION_JSON)
                .content("{" + credentials + "}")).andReturn().getResponse().getContentAsString());
    }

    @Test
    void scenario1AGuestBecomesAHostAndTheNextTokensCarryIt() throws Exception {
        String email = "guest-" + UUID.randomUUID() + "@example.com";
        JsonNode session = registerAndLogin(email);

        mvc.perform(post(UPGRADE).header("Authorization", "Bearer " + session.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles", containsInAnyOrder("HOST")))
                .andExpect(jsonPath("$.permissions").isArray());

        JsonNode next = login("\"email\":\"" + email + "\",\"password\":\"SecurePass123!\"");
        JsonNode claims = JSON.readTree(Base64.getUrlDecoder().decode(next.get("accessToken").asText().split("\\.")[1]));
        assertEquals("HOST", claims.get("roles").get(0).asText());
    }

    @Test
    void scenario2AnAccountThatIsAlreadyAHostIs422() throws Exception {
        String bearer = "Bearer " + registerAndLogin("guest-" + UUID.randomUUID() + "@example.com")
                .get("accessToken").asText();
        mvc.perform(post(UPGRADE).header("Authorization", bearer)).andExpect(status().isOk());

        mvc.perform(post(UPGRADE).header("Authorization", bearer))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error", is("INVALID_STATUS_TRANSITION")));
    }

    @Test
    void aServiceIsRefusedAndNoTokenIs401() throws Exception {
        mvc.perform(post(UPGRADE).header("Authorization", TestKeys.bearer("\"sub\":\"svc-workflow\",\"scope\":\"service\"")))
                .andExpect(status().isForbidden());
        mvc.perform(post(UPGRADE)).andExpect(status().isUnauthorized());
    }
}
