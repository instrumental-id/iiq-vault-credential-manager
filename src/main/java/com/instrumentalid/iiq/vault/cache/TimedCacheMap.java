package com.instrumentalid.iiq.vault.cache;

import lombok.Getter;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A thread-safe cache map that holds data with an expiration timestamp
 */
@Getter
public class TimedCacheMap {
    /**
     * The cached data map.
     */
    private final ConcurrentMap<String, Object> data;
    /**
     * The expiration timestamp in milliseconds.
     */
    private final long expirationTimestampMillis;

    /**
     * Constructor initializing the cache map with an expiration timestamp
     * @param expirationTimestampMillis the expiration timestamp in milliseconds
     */
    public TimedCacheMap(long expirationTimestampMillis) {
        this.expirationTimestampMillis = expirationTimestampMillis;
        this.data = new ConcurrentHashMap<>();
    }

    /**
     * Retrieves a value from the cache by key
     * @param key the key to look up
     * @return the cached value, or null if not found
     */
    public Object get(String key) {
        return data.get(key);
    }

    /**
     * Checks if the cached data has expired
     * @return true if expired, false otherwise
     */
    public boolean isExpired() {
        return System.currentTimeMillis() > expirationTimestampMillis;
    }
}
