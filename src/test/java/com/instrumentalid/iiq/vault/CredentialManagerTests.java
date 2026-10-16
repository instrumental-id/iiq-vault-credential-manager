package com.instrumentalid.iiq.vault;

import com.instrumentalid.iiq.vault.cache.DatabaseCredentialExtractor;
import com.instrumentalid.iiq.vault.cache.TokenCache;
import com.instrumentalid.iiq.vault.dto.VaultOptions;
import com.instrumentalid.iiq.vault.dto.VaultResponse;
import com.instrumentalid.iiq.vault.mocks.MockVaultClient;
import com.instrumentalid.iiq.vault.mocks.TestLogicalResponse;
import com.instrumentalid.iiq.vault.wrapper.RequestWrapper;
import com.instrumentalid.iiq.vault.wrapper.VaultCredentialManagerException;
import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import sailpoint.pam.credential.Configuration;
import sailpoint.pam.credential.Request;
import sailpoint.pam.credential.Response;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end tests for VaultCredentialManager and VaultCredentialService.
 * These tests verify the complete flow of credential retrieval including
 * caching, token management, and SSL configuration.
 */
@DisplayName("Vault Credential Manager E2E Tests")
public class CredentialManagerTests {

    @DisplayName("Vault File Retrieval Tests")
    @Nested
    class VaultFileRetrievalTests {

        @Test
        void testFileRetrieval() throws IOException {
            var config = new Configuration();
            var manager = new VaultCredentialManager(config, new MockVaultClient());

            // Write out to a file
            File tempFile = File.createTempFile("vault-test-", ".txt");
            tempFile.deleteOnExit();

            Files.writeString(tempFile.toPath(), "secret-file-content");

            var request = new Request(config);
            request.setAttributeName(tempFile.getAbsolutePath());
            request.put(Constants.TYPE, Constants.VAULT_TYPE_FILE);

            Response response = manager.getCredential(request);
            assertNotNull(response, "Response should not be null");

            assertEquals("secret-file-content", response.getString(request.getAttributeName()),
                    "File content should match expected value");
        }

        @Test
        void testFileRetrievalOfMap() throws IOException {
            var config = new Configuration();
            var manager = new VaultCredentialManager(config, new MockVaultClient());

            // Write out to a file
            File tempFile = File.createTempFile("vault-test-", ".json");
            tempFile.deleteOnExit();

            String fileContent = "{\"username\": \"admin\", \"password\": \"secret123\"}";

            Files.writeString(tempFile.toPath(), fileContent);

            var request = new Request(config);
            request.setAttributeName(tempFile.getAbsolutePath());
            request.put(Constants.TYPE, Constants.VAULT_TYPE_FILE);
            request.put(Constants.KEY, "password");

            Response response = manager.getCredential(request);
            assertNotNull(response, "Response should not be null");

            assertEquals("secret123", response.getString(request.getAttributeName()),
                    "Password should match expected value");
        }

        @Test
        @DisplayName("file retrieval throws when the file does not exist")
        void testFileRetrievalMissingFileThrows() {
            var config = new Configuration();
            var manager = new VaultCredentialManager(config, new MockVaultClient());

            var request = new Request(config);
            request.setAttributeName("/nonexistent/path/vault-test-missing.txt");
            request.put(Constants.TYPE, Constants.VAULT_TYPE_FILE);

            var e = assertThrows(VaultCredentialManagerException.class, () -> manager.getCredential(request),
                    "A missing file must not produce a null credential");
            assertTrue(e.getMessage().contains("404"), "Message should include the status");
            assertTrue(e.getMessage().contains("not found"), "Message should include the file error");
        }

        @Test
        @DisplayName("file retrieval throws when the requested field is missing")
        void testFileRetrievalMissingFieldThrows() throws IOException {
            var config = new Configuration();
            var manager = new VaultCredentialManager(config, new MockVaultClient());

            File tempFile = File.createTempFile("vault-test-", ".json");
            tempFile.deleteOnExit();
            Files.writeString(tempFile.toPath(), "{\"username\": \"admin\"}");

            var request = new Request(config);
            request.setAttributeName(tempFile.getAbsolutePath());
            request.put(Constants.TYPE, Constants.VAULT_TYPE_FILE);
            request.put(Constants.KEY, "password");

            var e = assertThrows(VaultCredentialManagerException.class, () -> manager.getCredential(request),
                    "A missing field must not produce a null credential");
            assertTrue(e.getMessage().contains("404"), "Message should include the status");
            assertTrue(e.getMessage().contains("'password'"), "Message should name the missing field");
        }

        @Test
        @DisplayName("file retrieval throws when the file is not readable")
        void testFileRetrievalUnreadableFileThrows() throws IOException {
            var config = new Configuration();
            var manager = new VaultCredentialManager(config, new MockVaultClient());

            File tempFile = File.createTempFile("vault-test-", ".txt");
            tempFile.deleteOnExit();
            Files.writeString(tempFile.toPath(), "secret");
            org.junit.jupiter.api.Assumptions.assumeTrue(tempFile.setReadable(false),
                    "Cannot make file unreadable on this platform");
            org.junit.jupiter.api.Assumptions.assumeFalse(Files.isReadable(tempFile.toPath()),
                    "Running as a user that can read anything (e.g. root)");

            var request = new Request(config);
            request.setAttributeName(tempFile.getAbsolutePath());
            request.put(Constants.TYPE, Constants.VAULT_TYPE_FILE);

            var e = assertThrows(VaultCredentialManagerException.class, () -> manager.getCredential(request));
            assertTrue(e.getMessage().contains("403"), "Message should include the status");
        }

        @Test
        @DisplayName("vault retrieval throws when the secret lacks the requested field")
        void testVaultRetrievalMissingFieldThrows() {
            var config = new Configuration();
            config.put(Constants.CONFIG_VAULT_URL, "https://vault.example.com");
            config.put(Constants.CONFIG_TOKEN, "test-token");
            var mockVaultClient = new MockVaultClient();
            var manager = new VaultCredentialManager(config, mockVaultClient);

            mockVaultClient.putSecret("kv/myapp/database", new HashMap<>(Map.of("username", "admin")));

            var request = new Request(config);
            request.setAttributeName("kv/myapp/database");
            request.put(Constants.KEY, "password");

            assertThrows(VaultCredentialManagerException.class, () -> manager.getCredential(request),
                    "Vault errors should still surface as exceptions after the check moved to the manager");
        }
    }

    /**
     * Unit tests for VaultCredentialService methods
     */
    @DisplayName("VaultCredentialService Tests")
    @Nested
    class VaultCredentialServiceTests {
        private Configuration config;
        private VaultOptions options;
        private Request request;
        private RequestWrapper requestWrapper;
        private VaultCredentialService service;

        @BeforeEach
        void setUp() throws Exception {
            config = new Configuration();
            config.put(Constants.CONFIG_VAULT_URL, "https://vault.example.com");
            config.put(Constants.CONFIG_TOKEN, "test-token");

            request = new Request(config);
            request.setAttributeName("kv/myapp/database");

            requestWrapper = new RequestWrapper((Request) request);
            options = new VaultOptions();
            options.path = "kv/myapp/database";
            options.field = "password";
            options.type = Constants.VAULT_TYPE_KV;
            options.engineVersion = 2;

            service = new VaultCredentialService((Configuration) config, requestWrapper, options);

            // Clear caches
            Field tokenField = TokenCache.class.getDeclaredField("tokenCache");
            tokenField.setAccessible(true);
            tokenField.set(TokenCache.getInstance(), new ConcurrentHashMap<>());

            Field dbField = DatabaseCredentialExtractor.class.getDeclaredField("cache");
            dbField.setAccessible(true);
            dbField.set(DatabaseCredentialExtractor.getInstance(), ThreadLocal.withInitial(ConcurrentHashMap::new));
        }

        @Test
        @DisplayName("buildSSLConfig throws when client key file not found")
        void testBuildSSLConfigThrowsWhenClientKeyFileNotFound() throws Exception {
            request.put(Constants.CLIENT_KEY_PEM_FILE, "/nonexistent/path/key.pem");
            requestWrapper = new RequestWrapper((Request) request);
            service = new VaultCredentialService((Configuration) config, requestWrapper, options);

            assertThrows(IllegalArgumentException.class,
                    () -> service.buildSSLConfig(),
                    "Should throw when client key file does not exist");
        }

        @Test
        @DisplayName("buildSSLConfig throws when server cert file not found")
        void testBuildSSLConfigThrowsWhenServerCertFileNotFound() throws Exception {
            request.put(Constants.SERVER_CERT_PEM_FILE, "/nonexistent/path/cert.pem");
            requestWrapper = new RequestWrapper((Request) request);
            service = new VaultCredentialService((Configuration) config, requestWrapper, options);

            assertThrows(IllegalArgumentException.class,
                    () -> service.buildSSLConfig(),
                    "Should throw when server cert file does not exist");
        }

        @Test
        @DisplayName("buildSSLConfig uses sslVerify setting from request")
        void testBuildSSLConfigUsesSslVerifySetting() throws Exception {
            request.put(Constants.SSL_VERIFY, "false");
            requestWrapper = new RequestWrapper((Request) request);
            service = new VaultCredentialService((Configuration) config, requestWrapper, options);

            SslConfig sslConfig = service.buildSSLConfig();

            assertFalse(sslConfig.isVerify(), "SslConfig should handle sslVerify setting");
        }

        @Test
        @DisplayName("buildSSLConfig returns valid SslConfig")
        void testBuildSSLConfigValid() throws Exception {
            SslConfig sslConfig = service.buildSSLConfig();

            assertNotNull(sslConfig, "SslConfig should not be null");
        }

        @Test
        @DisplayName("extractSecret returns error response for empty field")
        void testExtractSecretEmptyField() throws Exception {
            Map<String, Object> data = new HashMap<>();
            data.put("password", "");

            LogicalResponse logicalResponse = new TestLogicalResponse(data, 200);

            VaultResponse response = service.extractSecret(logicalResponse);

            assertNotNull(response, "Response should not be null");
            assertNotNull(response.getError(), "Error should not be null");
        }

        @Test
        @DisplayName("extractSecret returns error response for missing field")
        void testExtractSecretMissingField() throws Exception {
            Map<String, Object> data = new HashMap<>();
            data.put("username", "admin");
            // Missing "password" field

            LogicalResponse logicalResponse = new TestLogicalResponse(data, 200);

            VaultResponse response = service.extractSecret(logicalResponse);

            assertNotNull(response, "Response should not be null");
            assertNotNull(response.getError(), "Error should not be null");
            assertTrue(response.getError().contains("not found"), "Error should indicate field not found");
        }

        @Test
        @DisplayName("extractSecret uses DatabaseCredentialExtractor for database type")
        void testExtractSecretUsesDatabaseExtractorForDatabaseType() throws Exception {
            options.type = Constants.VAULT_TYPE_DATABASE;

            Map<String, Object> data = new HashMap<>();
            data.put("username", "admin");
            data.put("password", "secret123");

            LogicalResponse logicalResponse = new TestLogicalResponse(data, 200);

            // First, populate the cache with the response
            DatabaseCredentialExtractor extractor = DatabaseCredentialExtractor.getInstance();
            extractor.extractCredential(logicalResponse, options);

            // Now extract should use the cached values
            VaultResponse response = service.extractSecret(logicalResponse);

            assertNotNull(response, "Response should not be null");
            assertEquals(200, response.getStatus(), "Status should be 200");
        }

        @Test
        @DisplayName("extractSecret returns VaultResponse for valid response")
        void testExtractSecretValid() throws Exception {
            Map<String, Object> data = new HashMap<>();
            data.put("password", "secret123");

            LogicalResponse logicalResponse = new TestLogicalResponse(data, 200);

            VaultResponse response = service.extractSecret(logicalResponse);

            assertNotNull(response, "Response should not be null");
            assertEquals(200, response.getStatus(), "Status should be 200");
            assertEquals("secret123", response.getSecret(), "Secret should match");
            assertNull(response.getError(), "Error should be null");
        }

        @Test
        @DisplayName("getToken returns static token from configuration")
        void testGetTokenReturnsStaticToken() throws Exception {
            config.put(Constants.CONFIG_TOKEN, "static-token-12345");

            String token = service.getToken(service.buildSSLConfig());

            assertEquals("static-token-12345", token, "Should return static token from config");
        }

        @Test
        @DisplayName("getToken throws for unsupported auth type")
        void testGetTokenThrowsForUnsupportedAuthType() throws Exception {
            config.put(Constants.CONFIG_TOKEN, "");
            config.put(Constants.CONFIG_AUTH_TYPE, "unsupported");

            assertThrows(IllegalArgumentException.class,
                    () -> service.getToken(service.buildSSLConfig()),
                    "Should throw for unsupported auth type");
        }

        @Test
        @DisplayName("getToken throws when no auth method available")
        void testGetTokenThrowsWhenNoAuthMethod() throws Exception {
            config.put(Constants.CONFIG_TOKEN, "");
            config.put(Constants.CONFIG_AUTH_TYPE, null);

            assertThrows(IllegalArgumentException.class,
                    () -> service.getToken(service.buildSSLConfig()),
                    "Should throw when no auth method is configured");
        }

        @Test
        @DisplayName("readVaultResponse returns cached database credential when available")
        void testReadVaultResponseReturnsCachedDatabaseCredential() throws Exception {
            options.type = Constants.VAULT_TYPE_DATABASE;

            Map<String, Object> data = new HashMap<>();
            data.put("username", "admin");
            data.put("password", "cached-secret");

            LogicalResponse logicalResponse = new TestLogicalResponse(data, 200);

            // Populate the cache
            DatabaseCredentialExtractor extractor = DatabaseCredentialExtractor.getInstance();
            extractor.extractCredential(logicalResponse, options);

            VaultResponse response = service.readVaultResponse();

            assertNotNull(response, "Response should not be null");
            assertEquals("cached-secret", response.getSecret(), "Should return cached credential");
        }
    }

    /**
     * End-to-end tests for the credential retrieval flow via VaultCredentialManager
     */
    @DisplayName("Credential Retrieval Flow Tests")
    @Nested
    class CredentialRetrievalFlowTests {
        private Configuration config;
        private VaultCredentialManager manager;
        private MockVaultClient mockVaultClient;
        private Request request;

        @BeforeEach
        void setUp() throws Exception {
            config = new Configuration();
            config.put(Constants.CONFIG_VAULT_URL, "https://vault.example.com");
            config.put(Constants.CONFIG_AUTH_TYPE, Constants.VAULT_AUTH_APP_ROLE);
            config.put(Constants.CONFIG_ROLE_ID, "test-role-id");
            config.put(Constants.CONFIG_SECRET_ID, "test-secret-id");

            mockVaultClient = new MockVaultClient();

            manager = new VaultCredentialManager((Configuration) config, mockVaultClient);
            request = new Request(config);

            // Clear caches
            Field tokenField = TokenCache.class.getDeclaredField("tokenCache");
            tokenField.setAccessible(true);
            tokenField.set(TokenCache.getInstance(), new ConcurrentHashMap<>());

            Field dbField = DatabaseCredentialExtractor.class.getDeclaredField("cache");
            dbField.setAccessible(true);
            dbField.set(DatabaseCredentialExtractor.getInstance(), ThreadLocal.withInitial(ConcurrentHashMap::new));
        }

        @Test
        @DisplayName("credential retrieval flow with valid configuration")
        void testCredentialRetrievalFlowWithValidConfiguration() {
            request.setAttributeName("kv/myapp/database");
            request.put(Constants.ENGINE_VERSION, "2");
            request.put(Constants.KEY, "password");

            Map<String, Object> data = new HashMap<>();
            data.put("password", "super-secret-123");
            mockVaultClient.putSecret("kv/myapp/database", data);

            assertEquals("super-secret-123", manager.getCredential(request).getString("kv/myapp/database"),
                    "Should retrieve the expected secret value");
        }

        @Test
        @DisplayName("credential retrieval handles missing required parameters")
        void testCredentialRetrievalHandlesMissingRequiredParameters() {
            request.setAttributeName(null);

            assertThrows(VaultCredentialManagerException.class, () -> manager.getCredential(request),
                    "Should handle missing path gracefully");
        }

        @Test
        @DisplayName("database credential caching works across multiple requests")
        void testDatabaseCredentialCachingWorksAcrossRequests() throws Exception {
            VaultOptions options1 = new VaultOptions();
            options1.path = "database/postgres/role1";
            options1.field = "password";

            VaultOptions options2 = new VaultOptions();
            options2.path = "database/postgres/role1";
            options2.field = "username";

            Map<String, Object> data = new HashMap<>();
            data.put("username", "db_admin");
            data.put("password", "secret_pwd");

            LogicalResponse response = new TestLogicalResponse(data, 200);

            DatabaseCredentialExtractor extractor = DatabaseCredentialExtractor.getInstance();

            // Extract password
            String password = extractor.extractCredential(response, options1);
            assertEquals("secret_pwd", password, "Password should be extracted");

            // Username should be cached after first extraction
            String username = extractor.getCachedCredential(options2);
            assertEquals("db_admin", username, "Username should be cached");
        }

        @Test
        @DisplayName("options are correctly parsed from request")
        void testOptionsCorrectlyParsedFromRequest() {
            request.setAttributeName("kv/app/secret");
            request.put(Constants.TYPE, Constants.VAULT_TYPE_KV);
            request.put(Constants.KEY, "api_key");
            request.put(Constants.ENGINE_VERSION, "2");

            var requestWrapper = new RequestWrapper(request);

            VaultCredentialManager manager = new VaultCredentialManager((Configuration) config, mockVaultClient);
            VaultOptions options = manager.parseOptions(request, requestWrapper);


            assertEquals("kv/app/secret", options.path, "Path should be parsed correctly");
            assertEquals(Constants.VAULT_TYPE_KV, options.type, "Type should be parsed correctly");
            assertEquals("api_key", options.field, "Field should be parsed correctly");
            assertEquals(2, options.engineVersion, "Engine version should be parsed correctly");
        }

        @Test
        @DisplayName("token caching works across multiple requests")
        void testTokenCachingWorksAcrossRequests() {
            var key = new TokenCache.TokenKey("https://vault.example.com", "approle", "role-1");
            var otherKey = new TokenCache.TokenKey("https://vault.example.com", "approle", "role-2");

            TokenCache tokenCache = TokenCache.getInstance();
            tokenCache.putToken(key, "token-1", 3600);
            tokenCache.putToken(otherKey, "token-2", 3600);

            Optional<String> token1 = tokenCache.getToken(key);
            Optional<String> token2 = tokenCache.getToken(otherKey);

            assertTrue(token1.isPresent(), "Token 1 should be cached");
            assertTrue(token2.isPresent(), "Token 2 should be cached");
            assertEquals("token-1", token1.get());
            assertEquals("token-2", token2.get());
        }
    }

    /**
     * Tests that one login serves every path and field, and how auth failures are handled
     */
    @DisplayName("Shared Token Tests")
    @Nested
    class SharedTokenTests {
        private Configuration config;
        private MockVaultClient mockVaultClient;

        @BeforeEach
        void setUp() throws Exception {
            config = new Configuration();
            config.put(Constants.CONFIG_VAULT_URL, "https://vault.example.com");
            config.put(Constants.CONFIG_AUTH_TYPE, Constants.VAULT_AUTH_APP_ROLE);
            config.put(Constants.CONFIG_ROLE_ID, "role-1");
            config.put(Constants.CONFIG_SECRET_ID, "secret-1");

            mockVaultClient = new MockVaultClient();
            mockVaultClient.putSecret("kv/app1/secret", new HashMap<>(Map.of("user", "u1", "password", "p1")));
            mockVaultClient.putSecret("kv/app2/secret", new HashMap<>(Map.of("api_key", "k2")));

            Field tokenField = TokenCache.class.getDeclaredField("tokenCache");
            tokenField.setAccessible(true);
            tokenField.set(TokenCache.getInstance(), new ConcurrentHashMap<>());
        }

        private VaultResponse read(Configuration cfg, String path, String field) throws Exception {
            var request = new Request(cfg);
            request.setAttributeName(path);
            var options = new VaultOptions();
            options.path = path;
            options.field = field;
            options.type = Constants.VAULT_TYPE_KV;
            options.engineVersion = 2;
            var service = new VaultCredentialService(cfg, new RequestWrapper(request), options, mockVaultClient);
            return service.readVaultResponse();
        }

        @Test
        @DisplayName("different paths and fields share a single login")
        void testOneLoginForManyFields() throws Exception {
            assertEquals("u1", read(config, "kv/app1/secret", "user").getSecret());
            assertEquals("p1", read(config, "kv/app1/secret", "password").getSecret());
            assertEquals("k2", read(config, "kv/app2/secret", "api_key").getSecret());

            assertEquals(1, mockVaultClient.getLoginCount(), "All reads should reuse one token");
        }

        @Test
        @DisplayName("a different roleId gets its own login")
        void testDifferentRoleGetsOwnLogin() throws Exception {
            read(config, "kv/app1/secret", "user");

            var other = new Configuration();
            other.put(Constants.CONFIG_VAULT_URL, "https://vault.example.com");
            other.put(Constants.CONFIG_AUTH_TYPE, Constants.VAULT_AUTH_APP_ROLE);
            other.put(Constants.CONFIG_ROLE_ID, "role-2");
            other.put(Constants.CONFIG_SECRET_ID, "secret-2");
            read(other, "kv/app1/secret", "user");

            assertEquals(2, mockVaultClient.getLoginCount());
        }

        @Test
        @DisplayName("a 403 on a freshly issued token does not trigger a re-login")
        void testForbiddenFreshTokenDoesNotRelogin() throws Exception {
            mockVaultClient.putSecret("kv/denied", new HashMap<>(Map.of("password", "x")));
            mockVaultClient.forbidPath("kv/denied");

            VaultResponse denied = read(config, "kv/denied", "password");

            assertEquals(403, denied.getStatus());
            assertEquals(1, mockVaultClient.getLoginCount(), "A policy denial must not cause another login");
            assertEquals("u1", read(config, "kv/app1/secret", "user").getSecret());
            assertEquals(1, mockVaultClient.getLoginCount(), "The shared token should still be cached");
        }

        @Test
        @DisplayName("a 403 on an older cached token triggers one re-login and a retry")
        void testForbiddenOldTokenRelogins() throws Exception {
            read(config, "kv/app1/secret", "user");
            Thread.sleep(5100);

            mockVaultClient.rejectNextReads(1);
            VaultResponse response = read(config, "kv/app1/secret", "password");

            assertEquals("p1", response.getSecret(), "The retry with a new token should succeed");
            assertEquals(2, mockVaultClient.getLoginCount());
        }

        @Test
        @DisplayName("a 403 with a static token does not try to log in")
        void testForbiddenStaticTokenDoesNotRelogin() throws Exception {
            var staticConfig = new Configuration();
            staticConfig.put(Constants.CONFIG_VAULT_URL, "https://vault.example.com");
            staticConfig.put(Constants.CONFIG_TOKEN, "static");
            mockVaultClient.forbidPath("kv/app1/secret");

            VaultResponse response = read(staticConfig, "kv/app1/secret", "user");

            assertEquals(403, response.getStatus());
            assertEquals(0, mockVaultClient.getLoginCount());
        }
    }
}
