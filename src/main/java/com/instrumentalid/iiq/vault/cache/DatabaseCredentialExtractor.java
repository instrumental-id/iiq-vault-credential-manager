package com.instrumentalid.iiq.vault.cache;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.instrumentalid.iiq.vault.dto.VaultOptions;

import io.github.jopenlibs.vault.response.LogicalResponse;
import lombok.Setter;

/**
 * Singleton class responsible for extracting and caching database credentials
 * from Vault responses. Credentials are stored in a thread-local cache by path
 * and field name.
 *
 * Database credential responses can contain several fields (e.g., username and
 * password for a dynamic role) and this class caches all fields from a response
 * to avoid redundant Vault calls for subsequent field retrievals.
 */
public class DatabaseCredentialExtractor {
    /**
     * Singleton instance of DatabaseCredentialExtractor
     */
    private static final DatabaseCredentialExtractor INSTANCE = new DatabaseCredentialExtractor();
    /**
     * Key used to store the Vault path in the cache
     */
    private static final String PATH = "path";
    /**
     * Thread-local cache storing credential data per thread
     */
    private final ThreadLocal<ConcurrentMap<String, TimedCacheMap>> cache;

    /**
     * Private constructor initializing the thread-local cache.
     * Initializes a new ConcurrentHashMap for each thread.
     */
    private DatabaseCredentialExtractor() {
        this.cache = ThreadLocal.withInitial(ConcurrentHashMap::new);
    }

    /**
     * Returns the singleton instance of DatabaseCredentialExtractor.
     *
     * @return the singleton instance
     */
    public static DatabaseCredentialExtractor getInstance() {
        return INSTANCE;
    }

    /**
     * The cache timeout in seconds for credential entries. Defaults to 30 seconds,
     * can set for testing purposes.
     */
    @Setter
    private int cacheTimeoutSeconds = 30;

    /**
     * Extracts a credential value from the provided Vault response and caches it
     * for the current path.
     *
     * A Vault response can contain more than one field, any of which we may be
     * interested in for IIQ purposes. This method caches all fields from the
     * response so that subsequent calls to retrieve other fields do not require
     * another Vault call.
     *
     * @param response LogicalResponse from Vault containing credential data
     * @param options VaultOptions containing the path and field name to extract
     * @return the extracted credential value for the specified field
     * @throws IllegalArgumentException if the field is null or empty
     */
    public String extractCredential(LogicalResponse response, VaultOptions options) {
        // If the path has changed, we've moved on to a different Application, so clear the cache
        var threadLocalCache = this.cache.get();
        var path = options.path;

        TimedCacheMap cachedMap = threadLocalCache.get(path);
        if (cachedMap == null || cachedMap.isExpired()) {
            synchronized (this) {
                cachedMap = threadLocalCache.get(path);
                if (cachedMap == null || cachedMap.isExpired()) {
                    // TODO: make this expiration configurable?
                    threadLocalCache.put(path, new TimedCacheMap(System.currentTimeMillis() + cacheTimeoutSeconds * 1000L));
                }
            }
        }

        var field = options.field;
        if (field == null || field.isEmpty()) {
            throw new IllegalArgumentException("Key is required");
        }

        ConcurrentMap<String, Object> credentialMap = threadLocalCache.get(path).getData();
        if (credentialMap.get(field) != null) {
            // The requested field is already cached
            return (String) credentialMap.get(field);
        }

        // Not cached, put all credential data from the response into the Map
        for(String dataKey : response.getData().keySet()) {
            credentialMap.put(dataKey, response.getData().get(dataKey));
        }

        return (String) credentialMap.get(field);
    }

    /**
     * Retrieves a cached credential value for the specified field.
     * Does not perform any extraction; only returns previously cached credentials.
     *
     * @param options VaultOptions containing the field name to retrieve
     * @return the cached credential value, or null if not found in cache
     * @throws IllegalArgumentException if the field is null or empty
     */
    public String getCachedCredential(VaultOptions options) {
        String field = options.field;
        if (field == null || field.isEmpty()) {
            throw new IllegalArgumentException("Field is required");
        }

        String path = options.path;
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Path is required");
        }

        ConcurrentMap<String, TimedCacheMap> cacheMap = this.cache.get();

        if (cacheMap.get(path) != null) {
            ConcurrentMap<String, Object> credentialMap = cacheMap.get(path).getData();
            if (credentialMap.containsKey(field)) {
                return (String) credentialMap.get(field);
            }
        }
        return null;
    }

}
