package com.instrumentalid.iiq.vault.cache;

import io.github.jopenlibs.vault.VaultException;
import lombok.*;

import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class TokenCache {
    /**
     * A token is treated as expired this long before Vault would expire it, so we
     * don't hand out a token that dies mid-request. Capped at 10% of the lease for short leases.
     */
    private static final long EXPIRY_MARGIN_MILLIS = 30_000L;

    /**
     * A token younger than this that gets an authorization failure is assumed to be valid but
     * not permitted to read the path (Vault returns 403 for both), so re-authenticating won't help.
     */
    private static final long RECENTLY_ISSUED_MILLIS = 5_000L;

    /**
     * Identifies who a token was issued to: the Vault server plus the authentication identity.
     * Vault tokens carry the policies of the identity that logged in, not of any one secret, so
     * one token can read every path that identity is allowed to read.
     */
    @Getter
    @EqualsAndHashCode
    public static final class TokenKey {
        private final String url;
        private final String namespace;
        private final String authType;
        private final String identity;

        /**
         * @param url The Vault URL
         * @param namespace The Vault namespace (null or empty for the root namespace)
         * @param authType The authentication type (case-insensitive)
         * @param identity What identifies the login: the roleId for AppRole, or provider/role/path for JWT.
         *                 Never the secret itself.
         */
        public TokenKey(String url, String namespace, String authType, String identity) {
            this.url = url;
            this.namespace = namespace == null || namespace.isEmpty() ? null : namespace;
            this.authType = authType == null ? null : authType.toLowerCase(Locale.ROOT);
            this.identity = identity;
        }

        @Override
        public String toString() {
            return "TokenKey(url=" + url + ", namespace=" + namespace + ", authType=" + authType + ", identity=" + identity + ")";
        }
    }

    /**
     * Performs a Vault login. The implementation is expected to put the resulting token in the cache.
     */
    @FunctionalInterface
    public interface TokenLoader {
        String load() throws VaultException;
    }

    /**
     * Represents a cached token with its expiration time.
     */
    @Getter
    @EqualsAndHashCode
    @Builder
    private static class Token {
        private final long expirationMillis;
        private final long issuedMillis;
        private final String token;

        Token(long expirationMillis, long issuedMillis, String token) {
            this.expirationMillis = expirationMillis;
            this.issuedMillis = issuedMillis;
            this.token = token;
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > expirationMillis;
        }
    }

    /**
     * Singleton instance of TokenCache
     */
    private static final TokenCache INSTANCE = new TokenCache();

    /**
     * Thread-safe cache for tokens. The key is the Vault URL plus the authentication identity.
     */
    private final ConcurrentHashMap<TokenKey, Token> tokenCache = new ConcurrentHashMap<>();

    /**
     * Lock objects, one per key, so concurrent cache misses result in one login.
     */
    private final ConcurrentHashMap<TokenKey, Object> locks = new ConcurrentHashMap<>();

    /**
     * Private constructor to prevent instantiation
     */
    private TokenCache() {
        // private constructor to prevent instantiation
    }

    /**
     * Returns the singleton instance of TokenCache
     * @return The singleton instance of TokenCache
     */
    public static TokenCache getInstance() {
        return INSTANCE;
    }

    /**
     * Gets a token from the cache, or an empty optional if the token is expired or not found.
     * @param key The identity the token was issued to
     * @return An optional containing the token if it is found and not expired, or an empty optional otherwise.
     */
    public Optional<String> getToken(TokenKey key) {
        var token = tokenCache.get(key);

        if (token == null || token.isExpired()) {
            return Optional.empty();
        } else {
            return Optional.of(token.getToken());
        }
    }

    /**
     * Gets a token from the cache, or calls the loader to log in if there isn't a usable one.
     * If several threads miss at the same time, only one runs the loader and the rest use its token.
     * @param key The identity the token is for
     * @param loader Performs the login and caches the result via {@link #putToken}
     * @return The cached or newly obtained token
     * @throws VaultException If the login fails
     */
    public String getOrLoad(TokenKey key, TokenLoader loader) throws VaultException {
        Optional<String> cached = getToken(key);
        if (cached.isPresent()) {
            return cached.get();
        }

        Object lock = locks.computeIfAbsent(key, k -> new Object());
        synchronized (lock) {
            cached = getToken(key);
            if (cached.isPresent()) {
                return cached.get();
            }
            return loader.load();
        }
    }

    /**
     * Invalidates a token in the cache if it matches the existing token. If it
     * doesn't match, don't invalidate it, because somebody else already updated it.
     *
     * There's a minor timing problem here, but that's ok. If the token is invalidated
     * a few too many times, we just end up with a bunch of extra leases for a short time.
     *
     * @param key The identity the token was issued to
     * @param existingToken The existing token to be invalidated
     */
    public void invalidate(TokenKey key, String existingToken) {
        Optional<String> token = getToken(key);
        if (token.isPresent() && Objects.equals(existingToken, token.get())) {
            tokenCache.remove(key);
        }
    }

    /**
     * Decides whether an authorization failure (Vault returns 403 both for an expired token
     * and for a valid token without access to the path) is worth a re-login.
     *
     * It is if the token we used is no longer the cached one (someone else already replaced it,
     * or it expired), or if it is old enough that expiry is plausible. It is not if the token was
     * only just issued, since then the failure is almost certainly a policy denial and a re-login
     * would just evict the shared token for everyone.
     *
     * @param key The identity the token was issued to
     * @param usedToken The token that was rejected
     * @return true if the caller should invalidate and log in again
     */
    public boolean shouldRetryAfterAuthFailure(TokenKey key, String usedToken) {
        var cached = tokenCache.get(key);
        if (cached == null || cached.isExpired() || !Objects.equals(cached.getToken(), usedToken)) {
            return true;
        }
        return System.currentTimeMillis() - cached.getIssuedMillis() >= RECENTLY_ISSUED_MILLIS;
    }

    /**
     * Puts a token in the cache with an expiration time.
     * @param key The identity the token was issued to
     * @param token The token to be cached
     * @param durationSeconds The token duration retrieves from the Auth call
     */
    public void putToken(TokenKey key, String token, long durationSeconds) {
        long now = System.currentTimeMillis();
        long durationMillis = durationSeconds * 1000L;
        long margin = Math.min(EXPIRY_MARGIN_MILLIS, durationMillis / 10);
        tokenCache.put(key, Token.builder()
                .token(token)
                .issuedMillis(now)
                .expirationMillis(now + durationMillis - margin)
                .build());
    }
}
