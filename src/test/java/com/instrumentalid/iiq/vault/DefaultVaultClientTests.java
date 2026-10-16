package com.instrumentalid.iiq.vault;

import io.github.jopenlibs.vault.SslConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@DisplayName("DefaultVaultClient Tests")
public class DefaultVaultClientTests {
    private static final String URL = "https://vault.example.com";

    private DefaultVaultClient client(String namespace) throws Exception {
        return new DefaultVaultClient(URL, "tok", new SslConfig().build(), 2, namespace);
    }

    @Test
    @DisplayName("namespace is set on both login and read configurations")
    void testNamespaceAppliedToLoginAndRead() throws Exception {
        var client = client("admin/team-a");

        assertEquals("admin/team-a", client.buildConfig(false).getNameSpace());
        assertEquals("admin/team-a", client.buildConfig(true).getNameSpace());
    }

    @Test
    @DisplayName("namespace is trimmed")
    void testNamespaceTrimmed() throws Exception {
        assertEquals("team-a", client("  team-a ").buildConfig(true).getNameSpace());
    }

    @Test
    @DisplayName("null, empty and blank namespaces leave the namespace unset")
    void testNoNamespace() throws Exception {
        // The driver falls back to the VAULT_NAMESPACE environment variable when none is configured
        assumeTrue(System.getenv("VAULT_NAMESPACE") == null, "VAULT_NAMESPACE is set in this environment");
        assertNull(client(null).buildConfig(true).getNameSpace());
        assertNull(client("").buildConfig(true).getNameSpace());
        assertNull(client("   ").buildConfig(true).getNameSpace());
    }

    @Test
    @DisplayName("the four-argument constructor uses the root namespace")
    void testLegacyConstructor() throws Exception {
        assumeTrue(System.getenv("VAULT_NAMESPACE") == null, "VAULT_NAMESPACE is set in this environment");
        var client = new DefaultVaultClient(URL, "tok", new SslConfig().build(), 2);

        assertNull(client.buildConfig(true).getNameSpace());
    }

    @Test
    @DisplayName("the configured token is used for reads")
    void testTokenUsedForReads() throws Exception {
        assertEquals("tok", client(null).buildConfig(true).getToken());
    }
}
