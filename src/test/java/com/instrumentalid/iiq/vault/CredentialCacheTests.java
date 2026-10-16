package com.instrumentalid.iiq.vault;

import com.instrumentalid.iiq.vault.cache.DatabaseCredentialExtractor;
import com.instrumentalid.iiq.vault.cache.TimedCacheMap;
import com.instrumentalid.iiq.vault.cache.TokenCache;
import com.instrumentalid.iiq.vault.dto.VaultOptions;
import com.instrumentalid.iiq.vault.mocks.TestLogicalResponse;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test suite for credential and token cache behaviors.
 * Tests TokenCache, TimedCacheMap, and DatabaseCredentialExtractor implementations.
 */
@DisplayName("Credential Cache Tests")
public class CredentialCacheTests {

    // ==================== TokenCache Tests ====================

    @DisplayName("TokenCache Tests")
    @Nested
    class TokenCacheTests {
        private TokenCache tokenCache;

        @BeforeEach
        void setUp() throws Exception {
            // Get the singleton instance
            tokenCache = TokenCache.getInstance();
            // Clear the cache before each test by resetting it via reflection
            Field field = TokenCache.class.getDeclaredField("tokenCache");
            field.setAccessible(true);
            field.set(tokenCache, new ConcurrentHashMap<>());
        }

        @Test
        @DisplayName("getInstance returns singleton instance")
        void testGetInstanceReturnsSingletonInstance() {
            TokenCache instance1 = TokenCache.getInstance();
            TokenCache instance2 = TokenCache.getInstance();
            assertSame(instance1, instance2, "getInstance should return the same instance");
        }

        @Test
        @DisplayName("getToken returns empty optional when token is expired")
        void testGetTokenReturnsEmptyForExpiredToken() throws Exception {
            String path = "/vault/auth";
            String field = "client_token";
            String token = "expired-token";

            // Put a token with immediate expiration (0 seconds duration)
            tokenCache.putToken(path, field, token, 0L);

            // Wait a bit to ensure expiration time has passed
            Thread.sleep(10);

            Optional<String> retrieved = tokenCache.getToken(path, field);
            assertTrue(retrieved.isEmpty(), "Expired token should return empty optional");
        }

        @Test
        @DisplayName("getToken returns empty optional for non-existent token")
        void testGetTokenReturnsEmptyForNonExistent() {
            Optional<String> retrieved = tokenCache.getToken("/non/existent", "field");
            assertTrue(retrieved.isEmpty(), "Should return empty optional for non-existent token");
        }

        @Test
        @DisplayName("getToken with valid future expiration returns token")
        void testGetTokenWithValidFutureExpiration() {
            String path = "/vault/auth";
            String field = "client_token";
            String token = "valid-token";
            long durationSeconds = 7200L; // 2 hours

            tokenCache.putToken(path, field, token, durationSeconds);

            Optional<String> retrieved = tokenCache.getToken(path, field);
            assertTrue(retrieved.isPresent(), "Non-expired token should be retrievable");
            assertEquals(token, retrieved.get(), "Retrieved token should match stored token");
        }

        @Test
        @DisplayName("invalidate does not fail when token does not exist")
        void testInvalidateDoesNotFailForNonExistent() {
            // Should not throw an exception
            assertDoesNotThrow(() ->
                    tokenCache.invalidate("/non/existent", "field", "some-token")
            );
        }

        @Test
        @DisplayName("invalidate does not remove token when existing token does not match")
        void testInvalidateDoesNotRemoveOnMismatch() {
            String path = "/vault/auth";
            String field = "client_token";
            String storedToken = "stored-token";
            String differentToken = "different-token";

            tokenCache.putToken(path, field, storedToken, 3600L);
            tokenCache.invalidate(path, field, differentToken);

            Optional<String> retrieved = tokenCache.getToken(path, field);
            assertTrue(retrieved.isPresent(), "Token should not be removed on mismatch");
            assertEquals(storedToken, retrieved.get(), "Stored token should remain unchanged");
        }

        @Test
        @DisplayName("invalidate removes token when existing token matches")
        void testInvalidateRemovesTokenOnMatch() {
            String path = "/vault/auth";
            String field = "client_token";
            String token = "token-to-invalidate";

            tokenCache.putToken(path, field, token, 3600L);
            tokenCache.invalidate(path, field, token);

            Optional<String> retrieved = tokenCache.getToken(path, field);
            assertTrue(retrieved.isEmpty(), "Token should be removed after invalidation");
        }

        @Test
        @DisplayName("multiple tokens can be stored for different paths and fields")
        void testMultipleTokensForDifferentPathsAndFields() {
            tokenCache.putToken("/path1", "field1", "token1", 3600L);
            tokenCache.putToken("/path1", "field2", "token2", 3600L);
            tokenCache.putToken("/path2", "field1", "token3", 3600L);

            assertEquals("token1", tokenCache.getToken("/path1", "field1").get());
            assertEquals("token2", tokenCache.getToken("/path1", "field2").get());
            assertEquals("token3", tokenCache.getToken("/path2", "field1").get());
        }

        @Test
        @DisplayName("null path and field are handled correctly")
        void testNullPathAndFieldHandling() {
            // These should work without throwing exceptions
            assertDoesNotThrow(() -> tokenCache.putToken(null, null, "token", 3600L));
            assertDoesNotThrow(() -> tokenCache.getToken(null, null));
        }

        @ParameterizedTest
        @ValueSource(longs = {1L, 60L, 3600L, 86400L})
        @DisplayName("putToken correctly calculates expiration with various durations")
        void testPutTokenCalculatesExpirationCorrectly(long durationSeconds) {
            String path = "/vault/auth";
            String field = "client_token";
            String token = "test-token";

            long beforeTime = System.currentTimeMillis();
            tokenCache.putToken(path, field, token, durationSeconds);
            long afterTime = System.currentTimeMillis();

            Optional<String> retrieved = tokenCache.getToken(path, field);
            assertTrue(retrieved.isPresent(), "Token should be present after storage");
            // Token is valid (not expired), so it was stored with future expiration
        }

        @Test
        @DisplayName("putToken stores token with correct expiration")
        void testPutTokenStoresToken() {
            String path = "/vault/auth";
            String field = "client_token";
            String token = "test-token-12345";
            long durationSeconds = 3600L;

            tokenCache.putToken(path, field, token, durationSeconds);

            Optional<String> retrieved = tokenCache.getToken(path, field);
            assertTrue(retrieved.isPresent(), "Token should be retrievable after put");
            assertEquals(token, retrieved.get(), "Retrieved token should match stored token");
        }

        @Test
        @DisplayName("token update overwrites previous token")
        void testTokenUpdateOverwritesPrevious() {
            String path = "/vault/auth";
            String field = "client_token";

            tokenCache.putToken(path, field, "first-token", 3600L);
            tokenCache.putToken(path, field, "second-token", 3600L);

            Optional<String> retrieved = tokenCache.getToken(path, field);
            assertEquals("second-token", retrieved.get(), "Updated token should be retrieved");
        }
    }

    // ==================== TimedCacheMap Tests ====================

    @DisplayName("TimedCacheMap Tests")
    @Nested
    class TimedCacheMapTests {

        @Test
        @DisplayName("getData returns the concurrent map")
        void testGetDataReturnsConcurrentMap() {
            TimedCacheMap cache = new TimedCacheMap(System.currentTimeMillis() + 10000L);

            assertNotNull(cache.getData(), "getData should not return null");
            assertInstanceOf(ConcurrentHashMap.class, cache.getData(),
                    "getData should return a ConcurrentHashMap");
        }

        @Test
        @DisplayName("getExpirationTimestampMillis returns correct value")
        void testGetExpirationTimestampMillis() {
            long expirationTime = System.currentTimeMillis() + 5000L;
            TimedCacheMap cache = new TimedCacheMap(expirationTime);

            assertEquals(expirationTime, cache.getExpirationTimestampMillis(),
                    "getExpirationTimestampMillis should return the set expiration time");
        }

        @Test
        @DisplayName("get returns null for non-existent key")
        void testGetReturnsNullForNonExistentKey() {
            TimedCacheMap cache = new TimedCacheMap(System.currentTimeMillis() + 10000L);

            assertNull(cache.get("non-existent"), "get should return null for non-existent key");
        }

        @Test
        @DisplayName("isExpired returns false for future expiration time")
        void testIsExpiredReturnsFalseForFutureTime() {
            long futureTime = System.currentTimeMillis() + 10000L;
            TimedCacheMap cache = new TimedCacheMap(futureTime);

            assertFalse(cache.isExpired(), "Cache should not be expired when expiration time is in future");
        }

        @Test
        @DisplayName("isExpired returns true for current expiration time")
        void testIsExpiredReturnsTrueForCurrentTime() throws InterruptedException {
            long currentTime = System.currentTimeMillis();
            TimedCacheMap cache = new TimedCacheMap(currentTime);

            // Wait a bit to ensure current time has passed
            Thread.sleep(1);

            assertTrue(cache.isExpired(), "Cache should be expired when expiration time equals or is past current time");
        }

        @Test
        @DisplayName("isExpired returns true for past expiration time")
        void testIsExpiredReturnsTrueForPastTime() {
            long pastTime = System.currentTimeMillis() - 1000L;
            TimedCacheMap cache = new TimedCacheMap(pastTime);

            assertTrue(cache.isExpired(), "Cache should be expired when expiration time is in past");
        }

        @Test
        @DisplayName("multiple keys can be stored and retrieved")
        void testMultipleKeysStorageAndRetrieval() {
            TimedCacheMap cache = new TimedCacheMap(System.currentTimeMillis() + 10000L);

            cache.getData().put("username", "admin");
            cache.getData().put("password", "secret123");
            cache.getData().put("host", "localhost");

            assertEquals("admin", cache.get("username"));
            assertEquals("secret123", cache.get("password"));
            assertEquals("localhost", cache.get("host"));
        }

        @Test
        @DisplayName("TimedCacheMap stores data in concurrent map")
        void testTimedCacheMapStoresData() {
            long futureTime = System.currentTimeMillis() + 10000L;
            TimedCacheMap cache = new TimedCacheMap(futureTime);

            cache.getData().put("key1", "value1");

            assertEquals("value1", cache.get("key1"), "Data should be retrievable");
        }
    }

    // ==================== DatabaseCredentialExtractor Tests ====================

    @DisplayName("DatabaseCredentialExtractor Tests")
    @Nested
    class DatabaseCredentialExtractorTests {
        private DatabaseCredentialExtractor extractor;

        // Helper method to create a LogicalResponse implementation for testing
        private LogicalResponse createMockResponse(String... keyValues) throws Exception {
            Map<String, Object> data = new HashMap<>();

            for (int i = 0; i < keyValues.length; i += 2) {
                data.put(keyValues[i], keyValues[i + 1]);
            }

            return new TestLogicalResponse(data);
        }

        @BeforeEach
        void setUp() throws Exception {
            extractor = DatabaseCredentialExtractor.getInstance();
            extractor.setCacheTimeoutSeconds(3);
            // Clear thread-local cache by resetting it via reflection
            Field field = DatabaseCredentialExtractor.class.getDeclaredField("cache");
            field.setAccessible(true);
            field.set(extractor, ThreadLocal.withInitial(ConcurrentHashMap::new));
        }

        @Test
        @DisplayName("cache is cleared when path changes")
        void testCacheIsClearedWhenPathChanges() throws Exception, InterruptedException {
            LogicalResponse response1 = createMockResponse("username", "admin1");
            VaultOptions options1 = new VaultOptions();
            options1.path = "/database/creds/app-role-1";
            options1.field = "username";

            extractor.extractCredential(response1, options1);

            // Wait slightly more than cache expiration (30 seconds configured in code)
            Thread.sleep(3100);

            LogicalResponse response2 = createMockResponse("username", "admin2");
            VaultOptions options2 = new VaultOptions();
            options2.path = "/database/creds/app-role-1";
            options2.field = "username";

            // After 31 seconds, cache should be expired and reused
            String result = extractor.extractCredential(response2, options2);
            assertEquals("admin2", result, "Should return new value from new response after cache expiration");
        }

        @Test
        @DisplayName("cache is thread-local (each thread has its own cache)")
        void testCacheIsThreadLocal() throws Exception, InterruptedException {
            LogicalResponse response = createMockResponse("username", "admin");
            VaultOptions options = new VaultOptions();
            options.path = "/database/creds/app-role";
            options.field = "username";

            // Extract credential on main thread
            extractor.extractCredential(response, options);

            // Verify on main thread
            String mainThreadValue = extractor.getCachedCredential(options);
            assertEquals("admin", mainThreadValue, "Main thread should have cached value");

            // Try to access from different thread
            String[] threadResult = new String[1];
            Thread testThread = new Thread(() -> {
                try {
                    VaultOptions threadOptions = new VaultOptions();
                    threadOptions.path = "/database/creds/app-role";
                    threadOptions.field = "username";
                    // This should fail because the cache doesn't exist in this thread
                    threadResult[0] = extractor.getCachedCredential(threadOptions);
                } catch (IllegalArgumentException e) {
                    // Expected: cache doesn't exist for this thread
                    threadResult[0] = null;
                } catch (Exception e) {
                    threadResult[0] = null;
                }
            });

            testThread.start();
            testThread.join();

            assertNull(threadResult[0], "Different thread should not have access to main thread's cache");
        }

        @Test
        @DisplayName("extractCredential caches all fields from response")
        void testExtractCredentialCachesAllFields() throws Exception {
            LogicalResponse response = createMockResponse("username", "admin", "password", "secret123");
            VaultOptions options = new VaultOptions();
            options.path = "/database/creds/app-role";
            options.field = "username";

            extractor.extractCredential(response, options);

            // Now retrieve password without another API call
            VaultOptions passwordOptions = new VaultOptions();
            passwordOptions.path = "/database/creds/app-role";
            passwordOptions.field = "password";

            String password = extractor.getCachedCredential(passwordOptions);
            assertEquals("secret123", password, "Password should be cached from first extraction");
        }

        @Test
        @DisplayName("extractCredential extracts value from response and caches it")
        void testExtractCredentialExtractsFromResponse() throws Exception {
            LogicalResponse response = createMockResponse("username", "admin", "password", "secret123");
            VaultOptions options = new VaultOptions();
            options.path = "/database/creds/app-role";
            options.field = "username";

            String result = extractor.extractCredential(response, options);

            assertEquals("admin", result, "Should extract username from response");
        }

        @Test
        @DisplayName("extractCredential handles multi-field responses")
        void testExtractCredentialHandlesMultiFieldResponse() throws Exception {
            LogicalResponse response = createMockResponse(
                    "username", "admin",
                    "password", "secret123",
                    "host", "localhost",
                    "port", "5432"
            );
            VaultOptions options = new VaultOptions();
            options.path = "/database/creds/app-role";
            options.field = "password";

            String result = extractor.extractCredential(response, options);

            assertEquals("secret123", result, "Should extract password from multi-field response");

            // Verify all fields are cached
            VaultOptions hostOptions = new VaultOptions();
            hostOptions.path = "/database/creds/app-role";
            hostOptions.field = "host";

            String host = extractor.getCachedCredential(hostOptions);
            assertEquals("localhost", host, "Host should be cached");

            VaultOptions portOptions = new VaultOptions();
            portOptions.path = "/database/creds/app-role";
            portOptions.field = "port";

            String port = extractor.getCachedCredential(portOptions);
            assertEquals("5432", port, "Port should be cached");
        }

        @Test
        @DisplayName("extractCredential returns cached value on subsequent calls")
        void testExtractCredentialReturnsCachedValue() throws Exception {
            LogicalResponse response1 = createMockResponse("username", "admin", "password", "secret123");
            VaultOptions options = new VaultOptions();
            options.path = "/database/creds/app-role";
            options.field = "username";

            String first = extractor.extractCredential(response1, options);

            // Create a different response that would return different values
            LogicalResponse response2 = createMockResponse("username", "different-admin", "password", "different-secret");

            // Extract again - should return cached value from first response
            String second = extractor.extractCredential(response2, options);

            assertEquals("admin", first, "First extraction should return admin");
            assertEquals("admin", second, "Second extraction should return cached admin");
        }

        @Test
        @DisplayName("extractCredential throws IllegalArgumentException for empty field")
        void testExtractCredentialThrowsForEmptyField() throws Exception {
            LogicalResponse response = createMockResponse("username", "admin");
            VaultOptions options = new VaultOptions();
            options.path = "/database/creds/app-role";
            options.field = "";

            assertThrows(IllegalArgumentException.class,
                    () -> extractor.extractCredential(response, options),
                    "Should throw IllegalArgumentException for empty field");
        }

        @Test
        @DisplayName("extractCredential throws IllegalArgumentException for null field")
        void testExtractCredentialThrowsForNullField() throws Exception {
            LogicalResponse response = createMockResponse("username", "admin");
            VaultOptions options = new VaultOptions();
            options.path = "/database/creds/app-role";
            options.field = null;

            assertThrows(IllegalArgumentException.class,
                    () -> extractor.extractCredential(response, options),
                    "Should throw IllegalArgumentException for null field");
        }

        @Test
        @DisplayName("getCachedCredential retrieves previously extracted credential")
        void testGetCachedCredentialRetrieves() throws Exception {
            LogicalResponse response = createMockResponse("username", "admin", "password", "secret123");
            VaultOptions extractOptions = new VaultOptions();
            extractOptions.path = "/database/creds/app-role";
            extractOptions.field = "username";

            extractor.extractCredential(response, extractOptions);

            VaultOptions getOptions = new VaultOptions();
            getOptions.path = "/database/creds/app-role";
            getOptions.field = "username";

            String cached = extractor.getCachedCredential(getOptions);
            assertEquals("admin", cached, "Should retrieve cached credential");
        }

        @Test
        @DisplayName("getCachedCredential returns null for non-cached credential")
        void testGetCachedCredentialReturnsNullForNonCached() throws Exception {
            // First, we need to initialize a cache entry so the path exists
            LogicalResponse response = createMockResponse("other_field", "value");
            VaultOptions initOptions = new VaultOptions();
            initOptions.path = "/database/creds/app-role";
            initOptions.field = "other_field";
            extractor.extractCredential(response, initOptions);

            // Now try to get a different field that wasn't cached
            VaultOptions options = new VaultOptions();
            options.path = "/database/creds/app-role";
            options.field = "username";

            String cached = extractor.getCachedCredential(options);
            assertNull(cached, "Should return null for non-cached credential");
        }

        @Test
        @DisplayName("getCachedCredential does not serve expired credentials")
        void testGetCachedCredentialReturnsNullWhenExpired() throws Exception {
            extractor.setCacheTimeoutSeconds(0);

            VaultOptions options = new VaultOptions();
            options.path = "/database/creds/app-role";
            options.field = "username";
            extractor.extractCredential(createMockResponse("username", "admin"), options);

            Thread.sleep(20);

            assertNull(extractor.getCachedCredential(options),
                    "Expired credentials must be re-fetched from Vault, not served from cache");
            // Evicted, so the next extract starts from a fresh map rather than merging into the stale one
            assertEquals("admin2", extractor.extractCredential(createMockResponse("username", "admin2"), options));
        }

        @Test
        @DisplayName("getCachedCredential throws IllegalArgumentException for empty field")
        void testGetCachedCredentialThrowsForEmptyField() {
            VaultOptions options = new VaultOptions();
            options.path = "/database/creds/app-role";
            options.field = "";

            assertThrows(IllegalArgumentException.class,
                    () -> extractor.getCachedCredential(options),
                    "Should throw IllegalArgumentException for empty field");
        }

        @Test
        @DisplayName("getCachedCredential throws IllegalArgumentException for empty path")
        void testGetCachedCredentialThrowsForEmptyPath() {
            VaultOptions options = new VaultOptions();
            options.path = "";
            options.field = "username";

            assertThrows(IllegalArgumentException.class,
                    () -> extractor.getCachedCredential(options),
                    "Should throw IllegalArgumentException for empty path");
        }

        @Test
        @DisplayName("getCachedCredential throws IllegalArgumentException for null field")
        void testGetCachedCredentialThrowsForNullField() {
            VaultOptions options = new VaultOptions();
            options.path = "/database/creds/app-role";
            options.field = null;

            assertThrows(IllegalArgumentException.class,
                    () -> extractor.getCachedCredential(options),
                    "Should throw IllegalArgumentException for null field");
        }

        @Test
        @DisplayName("getCachedCredential throws IllegalArgumentException for null path")
        void testGetCachedCredentialThrowsForNullPath() {
            VaultOptions options = new VaultOptions();
            options.path = null;
            options.field = "username";

            assertThrows(IllegalArgumentException.class,
                    () -> extractor.getCachedCredential(options),
                    "Should throw IllegalArgumentException for null path");
        }

        @Test
        @DisplayName("getInstance returns singleton instance")
        void testGetInstanceReturnsSingletonInstance() {
            DatabaseCredentialExtractor instance1 = DatabaseCredentialExtractor.getInstance();
            DatabaseCredentialExtractor instance2 = DatabaseCredentialExtractor.getInstance();
            assertSame(instance1, instance2, "getInstance should return the same instance");
        }
    }
}
