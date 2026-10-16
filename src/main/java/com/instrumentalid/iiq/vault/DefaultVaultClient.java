package com.instrumentalid.iiq.vault;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.AuthResponse;
import io.github.jopenlibs.vault.response.LogicalResponse;
import lombok.Getter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Default implementation of VaultClient that uses the jopenlibs Vault driver
 */
@Getter
public class DefaultVaultClient implements VaultClient {
    /**
     * The default Vault engine version (KV version 2)
     */
    private static final int DEFAULT_ENGINE_VERSION = 2;

    /**
     * Default seconds to wait for a connection to Vault. Without an explicit value a hung Vault
     * can hold an IIQ worker thread indefinitely.
     */
    public static final int DEFAULT_OPEN_TIMEOUT_SECONDS = 10;

    /**
     * Default seconds to wait for Vault to respond once connected
     */
    public static final int DEFAULT_READ_TIMEOUT_SECONDS = 30;

    /**
     * The Vault engine version
     */
    private final int engineVersion;

    /**
     * The logger
     */
    private final Log log;

    /**
     * The SSL configuration
     */
    private final SslConfig sslConfig;
    /**
     * The Vault namespace, or null/empty for the root namespace
     */
    private final String namespace;
    /**
     * The authentication token
     */
    private final String token;
    /**
     * The Vault URL
     */
    private final String vaultUrl;
    /**
     * Seconds to wait when connecting to Vault
     */
    private final int openTimeoutSeconds;
    /**
     * Seconds to wait for a response from Vault
     */
    private final int readTimeoutSeconds;

    /**
     * Constructs a new DefaultVaultClient
     * @param vaultUrl The URL of the Vault instance
     * @param token The token to use for authentication (optional)
     * @param sslConfig The SSL configuration
     * @param engineVersion The Vault engine version
     */
    public DefaultVaultClient(String vaultUrl, String token, SslConfig sslConfig, int engineVersion) {
        this(vaultUrl, token, sslConfig, engineVersion, null);
    }

    /**
     * Constructs a new DefaultVaultClient
     * @param vaultUrl The URL of the Vault instance
     * @param token The token to use for authentication (optional)
     * @param sslConfig The SSL configuration
     * @param engineVersion The Vault engine version
     * @param namespace The Vault namespace to use for every request (optional; null or empty means root)
     */
    public DefaultVaultClient(String vaultUrl, String token, SslConfig sslConfig, int engineVersion, String namespace) {
        this(vaultUrl, token, sslConfig, engineVersion, namespace,
                DEFAULT_OPEN_TIMEOUT_SECONDS, DEFAULT_READ_TIMEOUT_SECONDS);
    }

    /**
     * Constructs a new DefaultVaultClient
     * @param vaultUrl The URL of the Vault instance
     * @param token The token to use for authentication (optional)
     * @param sslConfig The SSL configuration
     * @param engineVersion The Vault engine version
     * @param namespace The Vault namespace to use for every request (optional; null or empty means root)
     * @param openTimeoutSeconds Seconds to wait when connecting; must be positive
     * @param readTimeoutSeconds Seconds to wait for a response; must be positive
     * @throws IllegalArgumentException If either timeout is not positive
     */
    public DefaultVaultClient(String vaultUrl, String token, SslConfig sslConfig, int engineVersion, String namespace,
                              int openTimeoutSeconds, int readTimeoutSeconds) {
        if (openTimeoutSeconds <= 0 || readTimeoutSeconds <= 0) {
            throw new IllegalArgumentException("Vault timeouts must be positive (open=" + openTimeoutSeconds
                    + ", read=" + readTimeoutSeconds + ")");
        }
        this.openTimeoutSeconds = openTimeoutSeconds;
        this.readTimeoutSeconds = readTimeoutSeconds;
        this.vaultUrl = vaultUrl;
        this.namespace = namespace == null ? null : namespace.trim();
        this.token = token;
        this.sslConfig = sslConfig;
        this.engineVersion = engineVersion;
        this.log = LogFactory.getLog(DefaultVaultClient.class);
    }

    /**
     * Logs in to Vault using the AppRole authentication method
     * @param roleId The role ID
     * @param secretId The secret ID
     * @return The authentication response
     * @throws VaultException If an error occurs during authentication
     */
    @Override
    public AuthResponse loginByAppRole(String roleId, String secretId) throws VaultException {
        if (log.isDebugEnabled()) {
            log.debug("Logging in to Vault at " + vaultUrl + " using AppRole with roleId: " + roleId);
        }

        var vaultConfig = buildConfig(false);

        var vault = Vault.create(vaultConfig, DEFAULT_ENGINE_VERSION);
        return vault.auth().loginByAppRole(roleId, secretId);
    }

    /**
     * Logs in to Vault using the JWT authentication method
     * @param provider The JWT provider
     * @param role The JWT role
     * @param jwt The JWT token
     * @return The authentication response
     * @throws VaultException If an error occurs during authentication
     */
    @Override
    public AuthResponse loginByJwt(String provider, String role, String jwt) throws VaultException {
        if (log.isDebugEnabled()) {
            log.debug("Logging in to Vault at " + vaultUrl + " using JWT with provider: " + provider + " and role: " + role);
        }
        var vaultConfig = buildConfig(false);

        var vault = Vault.create(vaultConfig, DEFAULT_ENGINE_VERSION);
        return vault.auth().loginByJwt(provider, role, jwt);
    }

    /**
     * Logs in to Vault using the JWT authentication method with a custom auth path
     * @param provider The JWT provider
     * @param role The JWT role
     * @param jwt The JWT token
     * @param authPath The custom auth path
     * @return The authentication response
     * @throws VaultException If an error occurs during authentication
     */
    @Override
    public AuthResponse loginByJwt(String provider, String role, String jwt, String authPath) throws VaultException {
        if (log.isDebugEnabled()) {
            log.debug("Logging in to Vault at " + vaultUrl + " using JWT with provider: " + provider + ", role: " + role + ", and authPath: " + authPath);
        }
        var vaultConfig = buildConfig(false);

        var vault = Vault.create(vaultConfig, DEFAULT_ENGINE_VERSION);
        return vault.auth().loginByJwt(provider, role, jwt, authPath);
    }

    /**
     * Reads a secret from Vault at the specified path
     * @param path The path to the secret
     * @return The logical response containing the secret data
     * @throws VaultException If an error occurs during the read operation
     */
    @Override
    public LogicalResponse read(String path) throws VaultException {
        if (log.isDebugEnabled()) {
            log.debug("Reading secret from Vault at " + vaultUrl + " at path: " + path);
        }

        var vaultConfig = buildConfig(true);

        var vault = Vault.create(vaultConfig, engineVersion);
        return vault.logical().read(path);
    }

    /**
     * Builds the driver configuration for a request. The namespace is applied only when set, because
     * the driver rejects an empty one.
     * @param withToken Whether to include the token (reads do, logins don't)
     * @return The driver configuration
     * @throws VaultException If the configuration is invalid
     */
    VaultConfig buildConfig(boolean withToken) throws VaultException {
        var config = new VaultConfig()
                .address(vaultUrl)
                .sslConfig(sslConfig)
                .openTimeout(openTimeoutSeconds)
                .readTimeout(readTimeoutSeconds);
        if (withToken) {
            config.token(token);
        }
        // Don't call nameSpace() with an empty string: the driver throws "A namespace cannot be empty."
        if (namespace != null && !namespace.isEmpty()) {
            config.nameSpace(namespace);
        }
        return config.build();
    }
}
