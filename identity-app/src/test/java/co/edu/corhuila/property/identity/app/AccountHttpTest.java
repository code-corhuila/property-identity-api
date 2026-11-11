package co.edu.corhuila.property.identity.app;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
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
import org.springframework.test.web.servlet.ResultActions;

/** HU-IDENT-001 (E-10) and E-25, over HTTP with the in-memory adapters. */
@SpringBootTest
@AutoConfigureMockMvc
class AccountHttpTest {

    static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    MockMvc mvc;

    @DynamicPropertySource
    static void keys(DynamicPropertyRegistry registry) {
        TestKeys.register(registry);
    }

    static String email() {
        return "guest-" + UUID.randomUUID() + "@example.com";
    }

    ResultActions register(String email, String password, String key) throws Exception {
        String body = "{\"email\":\"" + email + "\",\"password\":\"" + password + "\",\"name\":\"María García\"}";
        var request = post("/api/v1/register").contentType(MediaType.APPLICATION_JSON).content(body);
        return mvc.perform(key == null ? request : request.header("Idempotency-Key", key));
    }

    @Test
    void aNewAccountIsAGuestWithItsFirstSession() throws Exception {
        String body = register(email(), "SecurePass123!", "reg-" + UUID.randomUUID())
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", "/api/v1/users/me"))
                .andExpect(jsonPath("$.expiresIn", is(3600)))
                .andExpect(jsonPath("$.refreshToken").isString())
                .andExpect(jsonPath("$.user.roles", containsInAnyOrder("GUEST")))
                .andExpect(jsonPath("$.user.name", is("María García")))
                .andExpect(jsonPath("$.user.permissions", hasItem("sagas:create")))
                .andExpect(jsonPath("$.user.permissions", not(hasItem("reservas:create"))))
                .andExpect(jsonPath("$.user.password").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        JsonNode auth = JSON.readTree(body);
        JsonNode claims = JSON.readTree(Base64.getUrlDecoder().decode(auth.get("accessToken").asText().split("\\.")[1]));
        assertEquals(auth.at("/user/id").asText(), claims.get("sub").asText());
        assertEquals("GUEST", claims.get("roles").get(0).asText());
        assertEquals(3600, claims.get("exp").asLong() - claims.get("iat").asLong());

        // The token Identity issued opens /users/me: the same account, with its permissions.
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer " + auth.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(auth.at("/user/id").asText())))
                .andExpect(jsonPath("$.roles", containsInAnyOrder("GUEST")))
                .andExpect(jsonPath("$.permissions.length()", is(8)));
    }

    @Test
    void aRepeatedKeyAnswers200WithTheAccountAndNoTokens() throws Exception {
        String email = email();
        String key = "reg-" + UUID.randomUUID();
        String id = JSON.readTree(register(email, "SecurePass123!", key).andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString()).at("/user/id").asText();

        register(email, "SecurePass123!", key)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(id)))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.refreshToken").doesNotExist());
    }

    @Test
    void anEmailAlreadyRegisteredIs422WhateverItsCase() throws Exception {
        String email = email();
        register(email, "SecurePass123!", "reg-" + UUID.randomUUID()).andExpect(status().isCreated());

        register(email.toUpperCase(), "SecurePass123!", "reg-" + UUID.randomUUID())
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error", is("BUSINESS_RULE_VIOLATION")))
                .andExpect(jsonPath("$.message", is("the e-mail is already registered")));
    }

    @Test
    void everyInvalidFieldAndTheMissingKeyAreNamed() throws Exception {
        mvc.perform(post("/api/v1/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"not-an-email\",\"password\":\"short\",\"name\":\" \"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("VALIDATION_ERROR")))
                .andExpect(jsonPath("$.details[*].field",
                        containsInAnyOrder("email", "password", "name", "Idempotency-Key")));
    }

    @Test
    void thePasswordNeedsAnUppercaseLetterAndADigit() throws Exception {
        for (String weak : new String[] {"alllowercase1", "NODIGITSHERE", "Sh0rt"}) {
            register(email(), weak, "reg-" + UUID.randomUUID())
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.details[0].field", is("password")));
        }
    }

    @Test
    void malformedJsonIs400WithTheEnvelope() throws Exception {
        mvc.perform(post("/api/v1/register").header("Idempotency-Key", "reg-12345678")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"email\":"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("VALIDATION_ERROR")))
                .andExpect(jsonPath("$.traceId").isString());
    }

    @Test
    void usersMeIsForPeople() throws Exception {
        mvc.perform(get("/api/v1/users/me").header("Authorization",
                        TestKeys.bearer("\"sub\":\"svc-workflow\",\"scope\":\"service\"")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error", is("FORBIDDEN")));
        mvc.perform(get("/api/v1/users/me").header("Authorization",
                        TestKeys.bearer("\"sub\":\"" + UUID.randomUUID() + "\"")))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/users/me").header("Authorization",
                        TestKeys.bearer("\"sub\":\"" + UUID.randomUUID() + "\",\"roles\":[\"GUEST\"]")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error", is("UNAUTHORIZED")));
    }
}
