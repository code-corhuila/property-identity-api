package co.edu.corhuila.property.identity.app;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** E-26 over HTTP: the contact of an account, for svc-notification only (GAP-017). */
@SpringBootTest
@AutoConfigureMockMvc
class ContactHttpTest {

    static final ObjectMapper JSON = new ObjectMapper();
    static final String NOTIFICATION = TestKeys.bearer("\"sub\":\"svc-notification\",\"scope\":\"service\"");

    @Autowired
    MockMvc mvc;

    @DynamicPropertySource
    static void keys(DynamicPropertyRegistry registry) {
        TestKeys.register(registry);
    }

    /** A new account: its id and the access token of its session. */
    JsonNode register(String email) throws Exception {
        return JSON.readTree(mvc.perform(post("/api/v1/register").header("Idempotency-Key", "reg-" + UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"SecurePass123!\",\"name\":\"Ana Pérez\"}"))
                .andReturn().getResponse().getContentAsString());
    }

    static String contact(String id) {
        return "/api/v1/users/" + id + "/contact";
    }

    @Test
    void notificationReadsTheEmailAndTheNameAndNothingElse() throws Exception {
        String email = "guest-" + UUID.randomUUID() + "@example.com";
        String id = register(email).at("/user/id").asText();

        mvc.perform(get(contact(id)).header("Authorization", NOTIFICATION))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(id)))
                .andExpect(jsonPath("$.email", is(email)))
                .andExpect(jsonPath("$.name", is("Ana Pérez")))
                .andExpect(jsonPath("$.roles").doesNotExist())
                .andExpect(jsonPath("$.permissions").doesNotExist());
    }

    @Test
    void aPersonEvenTheOwnerAndAnyOtherServiceGet403() throws Exception {
        JsonNode account = register("guest-" + UUID.randomUUID() + "@example.com");
        String id = account.at("/user/id").asText();

        mvc.perform(get(contact(id)).header("Authorization", "Bearer " + account.get("accessToken").asText()))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error", is("FORBIDDEN")));
        for (String service : new String[] {"svc-workflow", "svc-worker"}) {
            mvc.perform(get(contact(id)).header("Authorization",
                            TestKeys.bearer("\"sub\":\"" + service + "\",\"scope\":\"service\"")))
                    .andExpect(status().isForbidden());
        }
    }

    @Test
    void anUnknownIdIs404AMalformedOne400AndNoToken401() throws Exception {
        mvc.perform(get(contact(UUID.randomUUID().toString())).header("Authorization", NOTIFICATION))
                .andExpect(status().isNotFound()).andExpect(jsonPath("$.error", is("NOT_FOUND")));
        mvc.perform(get(contact("not-a-uuid")).header("Authorization", NOTIFICATION))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error", is("VALIDATION_ERROR")));
        mvc.perform(get(contact(UUID.randomUUID().toString())))
                .andExpect(status().isUnauthorized());
    }
}
