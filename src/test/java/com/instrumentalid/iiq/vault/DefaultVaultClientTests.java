package com.instrumentalid.iiq.vault;

import io.github.jopenlibs.vault.SslConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.jopenlibs.vault.VaultException;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;

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

    @Test
    @DisplayName("default timeouts are applied to both login and read configurations")
    void testDefaultTimeoutsApplied() throws Exception {
        var client = client(null);

        for (boolean withToken : new boolean[]{false, true}) {
            var config = client.buildConfig(withToken);
            assertEquals(DefaultVaultClient.DEFAULT_OPEN_TIMEOUT_SECONDS, config.getOpenTimeout());
            assertEquals(DefaultVaultClient.DEFAULT_READ_TIMEOUT_SECONDS, config.getReadTimeout());
        }
    }

    @Test
    @DisplayName("custom timeouts are applied; non-positive timeouts are rejected")
    void testCustomTimeouts() throws Exception {
        var client = new DefaultVaultClient(URL, "tok", new SslConfig().build(), 2, null, 3, 7);
        assertEquals(3, client.buildConfig(true).getOpenTimeout());
        assertEquals(7, client.buildConfig(true).getReadTimeout());

        assertThrows(IllegalArgumentException.class,
                () -> new DefaultVaultClient(URL, "tok", new SslConfig().build(), 2, null, 0, 7));
        assertThrows(IllegalArgumentException.class,
                () -> new DefaultVaultClient(URL, "tok", new SslConfig().build(), 2, null, 3, -1));
    }

    @Test
    @DisplayName("a Vault that accepts connections but never responds fails within the read timeout")
    void testHungVaultTimesOut() throws Exception {
        try (var server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            var client = new DefaultVaultClient("http://127.0.0.1:" + server.getLocalPort(), "tok",
                    new SslConfig().build(), 2, null, 2, 1);

            // Hold accepted sockets open without ever answering
            var accepted = new java.util.concurrent.CopyOnWriteArrayList<Socket>();
            var acceptor = new Thread(() -> {
                try {
                    while (!server.isClosed()) {
                        accepted.add(server.accept());
                    }
                } catch (Exception ignored) {
                    // server closed
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();

            try {
                var start = System.nanoTime();
                assertThrows(VaultException.class, () -> client.read("secret/data/foo"));
                var elapsed = Duration.ofNanos(System.nanoTime() - start);
                assertTrue(elapsed.compareTo(Duration.ofSeconds(10)) < 0, "Read did not time out promptly: " + elapsed);
            } finally {
                for (var socket : accepted) {
                    socket.close();
                }
            }
        }
    }
}
