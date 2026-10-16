package com.instrumentalid.iiq.vault.wrapper;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Helpers for producing log-safe views of configuration and request maps, so that
 * credentials never end up in IIQ log files.
 */
public class LogSanitizer {
    private static final String MASK = "********";

    private LogSanitizer() {
        // utility class
    }

    private static boolean isSensitive(String key) {
        if (key == null) {
            return false;
        }
        String k = key.toLowerCase(Locale.ROOT);
        if (k.equals("jwt") || k.contains("secretid") || k.contains("token") || k.contains("password")) {
            return true;
        }
        // Inline PEM contents are sensitive; the *File variants are just paths
        return k.contains("pem") && !k.endsWith("file");
    }
    
    /**
     * Returns a copy of the map with the values of sensitive keys (secret IDs, tokens,
     * JWTs, passwords, inline PEM material) replaced by a mask.
     *
     * @param map The map to sanitize (may be null)
     * @return A sanitized copy, or null if the input was null
     */
    public static Map<String, Object> mask(Map<String, ?> map) {
        if (map == null) {
            return null;
        }
        Map<String, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<String, ?> entry : map.entrySet()) {
            copy.put(entry.getKey(), isSensitive(entry.getKey()) && entry.getValue() != null ? MASK : entry.getValue());
        }
        return copy;
    }

}
