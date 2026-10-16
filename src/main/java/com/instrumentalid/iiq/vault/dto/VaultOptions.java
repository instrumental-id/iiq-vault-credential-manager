package com.instrumentalid.iiq.vault.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.StringJoiner;

/**
 * Data container for Vault options, passed around between various classes.
 * This should not be used outside of this library, so public visibility
 * is fine for fields.
 */
@Getter
@Setter
public class VaultOptions {
    /**
     * Flag indicating whether debug mode is enabled
     */
    public boolean debug;
    /**
     * The engine version (e.g., 1 or 2)
     */
    public int engineVersion;
    /**
     * The specific field within the secret to retrieve
     */
    public String field;
    /**
     * The path within Vault to the secret
     */
    public String path;

    /**
     * The Vault token to use for authentication
     */
    public String token;

    /**
     * The type of authentication (e.g., "token", "appRole", etc.)
     */
    public String type;

    @Override
    public String toString() {
        return new StringJoiner(", ", VaultOptions.class.getSimpleName() + "[", "]")
                .add("engineVersion=" + engineVersion)
                .add("field='" + field + "'")
                .add("path='" + path + "'")
                .add("token=" + (token == null ? "null" : "<set>"))
                .add("type='" + type + "'")
                .toString();
    }
}
