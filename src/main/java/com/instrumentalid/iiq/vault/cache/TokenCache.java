package com.instrumentalid.iiq.vault.cache;

import lombok.*;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Objects;

public class TokenCache {
    /**
     * Represents the unique name of a token based on its field and path.
     */
    @Getter
    @EqualsAndHashCode
    @AllArgsConstructor
    private static class TokenName {
        private final String field;
        private final String path;
    }

    /**
     * Represents a cached token with its expiration time.
     */
    @Getter
    @AllArgsConstructor
    @EqualsAndHashCode
    @Builder
    private static class Token {
        private final long expirationMillis;
        private final String token;

        public boolean isExpired() {
            return System.currentTimeMillis() > expirationMillis;
        }
    }

    /**
     * Singleton instance of TokenCache
     */
    private static final TokenCache INSTANCE = new TokenCache();

    /**
     * Thread-safe cache for tokens. The key is a combination of the path and field,
     */
    private final ConcurrentHashMap<TokenName, Token> tokenCache = new ConcurrentHashMap<>();

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
     * @param path The path of the request
     * @param field The field of the request
     * @return An optional containing the token if it is found and not expired, or an empty optional otherwise.
     */
    public Optional<String> getToken(String path, String field) {
        var tokenName = new TokenName(path, field);
        var token = tokenCache.get(tokenName);

        if (token == null || token.isExpired()) {
            return Optional.empty();
        } else {
            return Optional.of(token.getToken());
        }
    }

    /**
     * Invalidates a token in the cache if it matches the existing token. If it
     * doesn't match, don't invalidate it, because somebody else already updated it.
     *
     * There's a minor timing problem here, but that's ok. If the token is invalidated
     * a few too many times, we just end up with a bunch of extra leases for a short time.
     *
     * @param path The path of the request
     * @param field The field of the request
     * @param existingToken The existing token to be invalidated
     */
    public void invalidate(String path, String field, String existingToken) {
        Optional<String> token = getToken(path, field);
        if (token.isPresent() && Objects.equals(existingToken, token.get())) {
            tokenCache.remove(new TokenName(path, field));
        }
    }

    /**
     * Puts a token in the cache with an expiration time.
     * @param path The path of the request
     * @param field The field of the request
     * @param token The token to be cached
     * @param durationSeconds The token duration retrieves from the Auth call
     */
    public void putToken(String path, String field, String token, long durationSeconds) {
        long expirationMillis = System.currentTimeMillis() + (durationSeconds * 1000L);
        var tokenName = new TokenName(path, field);
        tokenCache.put(tokenName, Token.builder()
                .token(token)
                .expirationMillis(expirationMillis)
                .build());
    }
}
