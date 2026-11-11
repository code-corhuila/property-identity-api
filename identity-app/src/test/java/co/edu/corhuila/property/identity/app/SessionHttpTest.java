package co.edu.corhuila.property.identity.app;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/** HU-IDENT-002 over HTTP: E-11 login, E-12 refresh, E-13 logout, and E-25 with the issued token. */
@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class SessionHttpTest {

    static final ObjectMapper JSON = new ObjectMapper();
    static final String PASSWORD = "SecurePass123!";

    @Autowired
    MockMvc mvc;

    String email;

    @DynamicPropertySource
    static void keys(DynamicPropertyRegistry registry) {
        TestKeys.register(registry);
    }

    @BeforeEach
    void anAccount() throws Exception {
        email = "guest-" + UUID.randomUUID() + "@example.com";
        mvc.perform(post("/api/v1/register").header("Idempotency-Key", "reg-" + UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\",\"name\":\"Ana\"}"))
                .andExpect(status().isCreated());
    }

    ResultActions call(String path, String body, String bearer) throws Exception {
        var request = post(path).contentType(MediaType.APPLICATION_JSON).content(body);
        return mvc.perform(bearer == null ? request : request.header("Authorization", "Bearer " + bearer));
    }

    ResultActions login(String password) throws Exception {
        return call("/api/v1/login", "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}", null);
    }

    JsonNode session() throws Exception {
        return JSON.readTree(login(PASSWORD).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    ResultActions refresh(String token) throws Exception {
        return call("/api/v1/refresh", "{\"refreshToken\":\"" + token + "\"}", null);
    }

    @Test
    void scenario1ValidCredentialsGiveAnAccessTokenOfOneHourAndARefreshToken() throws Exception {
        login(PASSWORD).andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString())
                .andExpect(jsonPath("$.expiresIn", is(3600)))
                .andExpect(jsonPath("$.user.email", is(email)));
    }

    @Test
    void scenario2WrongPasswordIs401AndTheFifthLocksTheAccount() throws Exception {
        String message = JSON.readTree(login("WrongPass1").andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error", is("UNAUTHORIZED")))
                .andReturn().getResponse().getContentAsString()).get("message").asText();
        for (int i = 0; i < 4; i++) {
            login("WrongPass1").andExpect(status().isUnauthorized());
        }
        login(PASSWORD).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.message", is(message)));
        call("/api/v1/login", "{\"email\":\"nadie@example.com\",\"password\":\"x\"}", null)
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.message", is(message)));
    }

    @Test
    void scenario3RenewalRotatesAndAReusedTokenRevokesEverySession() throws Exception {
        JsonNode first = session();
        JsonNode other = session();
        JsonNode renewed = JSON.readTree(refresh(first.get("refreshToken").asText())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refreshToken", not(first.get("refreshToken").asText())))
                .andExpect(jsonPath("$.expiresIn", is(3600)))
                .andReturn().getResponse().getContentAsString());

        refresh(first.get("refreshToken").asText()).andExpect(status().isUnauthorized());
        refresh(renewed.get("refreshToken").asText()).andExpect(status().isUnauthorized());
        refresh(other.get("refreshToken").asText()).andExpect(status().isUnauthorized());
    }

    @Test
    void scenario4AfterLogoutTheSessionCannotBeRenewed() throws Exception {
        JsonNode s = session();
        call("/api/v1/logout", "{\"refreshToken\":\"" + s.get("refreshToken").asText() + "\"}", s.get("accessToken").asText())
                .andExpect(status().isNoContent());

        refresh(s.get("refreshToken").asText()).andExpect(status().isUnauthorized());
    }

    @Test
    void logoutOnEveryDeviceAndItsValidation() throws Exception {
        JsonNode a = session();
        JsonNode b = session();
        String access = a.get("accessToken").asText();

        call("/api/v1/logout", "{}", access).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("VALIDATION_ERROR")));
        call("/api/v1/logout", "{\"allDevices\":true}", null).andExpect(status().isUnauthorized());
        call("/api/v1/logout", "{\"allDevices\":true}", access).andExpect(status().isNoContent());

        refresh(a.get("refreshToken").asText()).andExpect(status().isUnauthorized());
        refresh(b.get("refreshToken").asText()).andExpect(status().isUnauthorized());
    }

    @Test
    void scenario5MyAccountWithTheIssuedToken() throws Exception {
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + session().get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email", is(email)))
                .andExpect(jsonPath("$.name", is("Ana")))
                .andExpect(jsonPath("$.roles", containsInAnyOrder("GUEST")))
                .andExpect(jsonPath("$.permissions").isArray());
    }

    @Test
    void missingFieldsAre400AndNameEachOne() throws Exception {
        call("/api/v1/login", "{}", null).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[*].field", containsInAnyOrder("email", "password")));
        call("/api/v1/refresh", "{}", null).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[0].field", is("refreshToken")));
    }

    /** security-policy.md: the user goes as its sub; never the e-mail, the password or a token. */
    @Test
    void theSecurityLogNamesTheUserBySubAndNeverByEmailPasswordOrToken(CapturedOutput output) throws Exception {
        login("WrongPass1").andExpect(status().isUnauthorized());
        JsonNode s = session();
        refresh(s.get("refreshToken").asText()).andExpect(status().isOk());
        refresh(s.get("refreshToken").asText()).andExpect(status().isUnauthorized());
        call("/api/v1/login", "{\"email\":\"nadie@example.com\",\"password\":\"x\"}", null);

        String sub = s.at("/user/id").asText();
        String security = String.join(System.lineSeparator(),
                output.getOut().lines().filter(l -> l.contains("\"security\"")).toList());
        assertTrue(security.contains("auth.login.failure result=FAILURE userId=" + sub), security);
        assertTrue(security.contains("auth.login.success result=SUCCESS userId=" + sub), security);
        assertTrue(security.contains("refresh-token-reuse userId=" + sub), security);
        assertTrue(security.contains("userId=ANONYMOUS"), security);
        for (String secret : new String[] {email, "nadie@example.com", PASSWORD, "WrongPass1",
                s.get("refreshToken").asText(), s.get("accessToken").asText()}) {
            assertFalse(output.getOut().contains(secret), "the log must not contain " + secret);
        }
    }
}
