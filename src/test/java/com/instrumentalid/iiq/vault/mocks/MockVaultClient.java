package com.instrumentalid.iiq.vault.mocks;

import com.instrumentalid.iiq.vault.VaultClient;
import com.instrumentalid.iiq.vault.VaultCredentialManager;
import io.github.jopenlibs.vault.response.AuthResponse;
import io.github.jopenlibs.vault.response.LogicalResponse;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Mock implementation of VaultClient for testing. Allows mocking the various
 * Vault interactions by predefining responses and passing to {@link VaultCredentialManager}
 */
public class MockVaultClient implements VaultClient {
    /**
     * The next auth duration to return on login
     */
    private long nextAuthDuration = 3600;

    /**
     * The next auth token to return on login
     */
    private String nextAuthToken = "mock-auth-token";

    /**
     * The secret store to simulate stored secrets
     */
    private final Map<String, Map<String, Object>> secretStore;

    /**
     * Paths that respond with 403, like a valid token that the policy doesn't allow to read them
     */
    private final Set<String> forbiddenPaths = new HashSet<>();

    /**
     * How many logins have been performed
     */
    private final AtomicInteger loginCount = new AtomicInteger();

    /**
     * How many 403 responses to give regardless of path (simulates an expired token), counting down
     */
    private int rejectNextReads = 0;

    public MockVaultClient() {
        this.secretStore = new HashMap<>();
    }

    /**
     * Simulates authenticating with Vault using AppRole authentication
     * @param roleId The role ID
     * @param secretId The secret ID
     * @return The authentication response
     */
    @Override
    public AuthResponse loginByAppRole(String roleId, String secretId) {
        loginCount.incrementAndGet();
        try {
            AuthResponse response = new AuthResponse(new TestRestResponse(200, null), 0);
            // Use reflection to set auth client token and lease duration
            Field tokenField = AuthResponse.class.getDeclaredField("authClientToken");
            tokenField.setAccessible(true);
            tokenField.set(response, nextAuthToken);

            Field durationField = AuthResponse.class.getDeclaredField("authLeaseDuration");
            durationField.setAccessible(true);
            durationField.set(response, nextAuthDuration);

            return response;
        } catch (Exception e) {
            throw new RuntimeException("Error creating mock auth response", e);
        }
    }

    @Override
    public AuthResponse loginByJwt(String provider, String role, String jwt) {
        return loginByAppRole("", "");
    }

    @Override
    public AuthResponse loginByJwt(String provider, String role, String jwt, String authPath) {
        return loginByAppRole("", "");
    }

    public void putSecret(String path, Map<String, Object> data) {
        secretStore.put(path, data);
    }

    /**
     * Simulates reading a secret from Vault. Simulated secrets must be first added
     * via {@link #putSecret(String, Map)}.
     *
     * @param path The path to the secret
     * @return The logical response containing the secret data
     */
    @Override
    public LogicalResponse read(String path) {
        if (rejectNextReads > 0) {
            rejectNextReads--;
            return new TestLogicalResponse(new HashMap<>(), 403);
        }
        if (forbiddenPaths.contains(path)) {
            return new TestLogicalResponse(new HashMap<>(), 403);
        }
        Map<String, Object> data = secretStore.get(path);
        if (data == null) {
            throw new RuntimeException("Secret not found at path: " + path);
        }
        return new TestLogicalResponse(data, 200);
    }

    /**
     * Sets the next auth token and duration to return on login
     * @param token The auth token to return
     * @param duration The lease duration to return
     */
    public void setNextAuthToken(String token, long duration) {
        this.nextAuthToken = token;
        this.nextAuthDuration = duration;
    }

    public void forbidPath(String path) {
        forbiddenPaths.add(path);
    }

    public void rejectNextReads(int count) {
        this.rejectNextReads = count;
    }

    public int getLoginCount() {
        return loginCount.get();
    }
}
