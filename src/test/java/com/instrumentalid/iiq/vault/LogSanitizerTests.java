package com.instrumentalid.iiq.vault;

import com.instrumentalid.iiq.vault.dto.VaultOptions;
import com.instrumentalid.iiq.vault.wrapper.LogSanitizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Log sanitization Tests")
public class LogSanitizerTests {

    @ParameterizedTest
    @ValueSource(strings = {
            Constants.CONFIG_SECRET_ID,
            Constants.CONFIG_TOKEN,
            Constants.CONFIG_JWT,
            Constants.CLIENT_KEY_PEM_UTF8,
            Constants.SERVER_CERT_PEM_UTF8
    })
    @DisplayName("masks every credential-bearing config key")
    void masksSensitiveKeys(String key) {
        Map<String, Object> masked = LogSanitizer.mask(Map.of(key, "super-secret-value"));

        assertFalse(masked.toString().contains("super-secret-value"), key + " value leaked");
        assertTrue(masked.containsKey(key), "Key should remain so the log still shows it was set");
    }

    @Test
    @DisplayName("keeps non-secret settings readable, including PEM file paths and jwt role/provider")
    void keepsNonSensitiveKeys() {
        Map<String, Object> input = new HashMap<>();
        input.put(Constants.CONFIG_ROLE_ID, "role-123");
        input.put(Constants.CONFIG_VAULT_URL, "https://vault.example.test:8200");
        input.put(Constants.CONFIG_JWT_ROLE, "my-role");
        input.put(Constants.CONFIG_JWT_PROVIDER, "jwt");
        input.put(Constants.CLIENT_KEY_PEM_FILE, "/etc/vault/client.pem");
        input.put(Constants.SERVER_CERT_PEM_FILE, "/etc/vault/server.pem");
        input.put(Constants.TYPE, "database");

        assertEquals(input, LogSanitizer.mask(input));
    }

    @Test
    @DisplayName("does not mutate the original map and leaves unset sensitive values as null")
    void copiesInputAndPreservesNulls() {
        Map<String, Object> input = new HashMap<>();
        input.put(Constants.CONFIG_SECRET_ID, "abc");
        input.put(Constants.CONFIG_TOKEN, null);

        Map<String, Object> masked = LogSanitizer.mask(input);

        assertEquals("abc", input.get(Constants.CONFIG_SECRET_ID), "Original map must be untouched");
        assertNotEquals("abc", masked.get(Constants.CONFIG_SECRET_ID));
        assertNull(masked.get(Constants.CONFIG_TOKEN), "Absence of a token should stay visible when debugging");
    }

    @Test
    @DisplayName("VaultOptions.toString never includes the token")
    void optionsToStringHidesToken() {
        VaultOptions options = new VaultOptions();
        options.path = "kv/app";
        options.token = "s.abcdef123456";

        String text = options.toString();

        assertFalse(text.contains("s.abcdef123456"));
        assertTrue(text.contains("kv/app"));
    }
}
