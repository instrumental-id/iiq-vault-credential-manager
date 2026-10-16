package com.instrumentalid.iiq.vault;

import com.instrumentalid.iiq.vault.dto.VaultOptions;
import com.instrumentalid.iiq.vault.mocks.MockVaultClient;
import com.instrumentalid.iiq.vault.wrapper.RequestWrapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import sailpoint.pam.credential.Configuration;
import sailpoint.pam.credential.Request;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("Vault timeout configuration")
public class TimeoutConfigTests {
    private VaultCredentialService service(Configuration config) {
        var request = new Request(config);
        request.setAttributeName("kv/app/secret");
        var options = new VaultOptions();
        options.path = "kv/app/secret";
        options.engineVersion = 2;
        return new VaultCredentialService(config, new RequestWrapper(request), options, new MockVaultClient());
    }

    private Configuration config(String key, Object value) {
        var config = new Configuration();
        if (key != null) {
            config.put(key, value);
        }
        return config;
    }

    @Test
    @DisplayName("unset or blank values fall back to the default; valid values are used; garbage fails loudly")
    void testParsing() {
        var key = Constants.CONFIG_READ_TIMEOUT_SECONDS;

        assertEquals(30, service(config(null, null)).getTimeoutSeconds(key, 30));
        assertEquals(30, service(config(key, "  ")).getTimeoutSeconds(key, 30));
        assertEquals(5, service(config(key, " 5 ")).getTimeoutSeconds(key, 30));
        assertEquals(8, service(config(key, 8)).getTimeoutSeconds(key, 30));

        for (var bad : new String[]{"0", "-3", "fast", "1.5"}) {
            assertThrows(IllegalArgumentException.class, () -> service(config(key, bad)).getTimeoutSeconds(key, 30), bad);
        }
    }
}
