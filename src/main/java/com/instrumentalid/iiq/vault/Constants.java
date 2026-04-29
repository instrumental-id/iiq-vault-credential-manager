package com.instrumentalid.iiq.vault;

/**
 * Constants used in the VaultCredentialManager.
 */
public class Constants {
    /**
     * The key used to identify the client key in PEM format as a file.
     */
    public static final String CLIENT_KEY_PEM_FILE = "clientKeyPemFile";
    /**
     * Error message when the client key PEM file does not exist.
     */
    public static final String CLIENT_KEY_PEM_FILE_NOT_EXIST = "clientKeyPemFile does not exist";
    /**
     * The key used to identify the client key in PEM format as a UTF-8 string.
     */
    public static final String CLIENT_KEY_PEM_UTF8 = "clientKeyPemUTF8";
    /**
     * The authentication type (e.g., "jwt", "appRole", etc.).
     */
    public static final String CONFIG_AUTH_TYPE = "authType";
    /**
     * The JWT token itself for JWT authentication.
     */
    public static final String CONFIG_JWT = "jwt";

    /**
     * The JWT authentication path in Vault.
     */
    public static final String CONFIG_JWT_AUTH_PATH = "jwtAuthPath";

    /**
     * The JWT provider name in Vault.
     */
    public static final String CONFIG_JWT_PROVIDER = "jwtProvider";

    /**
     * The JWT role name in Vault.
     */
    public static final String CONFIG_JWT_ROLE = "jwtRole";

    /**
     * The role ID for AppRole authentication.
     */
    public static final String CONFIG_ROLE_ID = "roleId";

    /**
     * The secret ID for AppRole authentication.
     */
    public static final String CONFIG_SECRET_ID = "secretId";
    /**
     * Default value name for key-value pairs.
     */
    public static final String DEFAULT_VALUE_NAME = "value";
    /**
     * The Vault engine version (e.g., 1 or 2).
     */
    public static final String ENGINE_VERSION = "engineVersion";
    /**
     * Error message when unable to retrieve a credential.
     */
    public static final String ERROR_GETTING_CREDENTIAL = "Error getting credential";
    /**
     * The key used to identify the main key in key-value pairs.
     */
    public static final String KEY = "key";
    /**
     * Error message when the kvPath parameter is required but not provided.
     */
    public static final String KV_PATH_REQUIRED = "kvPath is required";
    /**
     * The key used to identify the server certificate in PEM format as a file.
     */
    public static final String SERVER_CERT_PEM_FILE = "serverCertPemFile";
    /**
     * Error message when the server certificate PEM file does not exist.
     */
    public static final String SERVER_CERT_PEM_FILE_NOT_EXIST = "serverCertPemFile does not exist";
    /**
     * The key used to identify the server certificate in PEM format as a UTF-8 string.
     */
    public static final String SERVER_CERT_PEM_UTF8 = "serverCertPemUTF8";
    /**
     * The key used to identify whether SSL verification is enabled.
     */
    public static final String SSL_VERIFY = "sslVerify";
    /**
     * The key used to identify the authentication token.
     */
    public static final String CONFIG_TOKEN = "token";
    /**
     * The secret type (e.g., "kv", "database", etc.).
     */
    public static final String TYPE = "secretType";
    /**
     * The key used to identify the URL for the Vault server.
     */
    public static final String CONFIG_VAULT_URL = "url";

    /**
     * The auth type name for AppRole authentication.
     */
    public static final String VAULT_AUTH_APP_ROLE = "appRole";

    /**
     * The auth type name for JWT authentication.
     */
    public static final String VAULT_AUTH_JWT = "jwt";

    /**
     * The secret type name for database secrets.
     */
    public static final String VAULT_TYPE_DATABASE = "database";

    /**
     * Secrets are stored on the filesystem by, e.g., Vault Agent
     */
    public static final String VAULT_TYPE_FILE = "file";

    /**
     * The secret type name for key-value secrets (V1 or V2).
     */
    public static final String VAULT_TYPE_KV = "kv";
}
