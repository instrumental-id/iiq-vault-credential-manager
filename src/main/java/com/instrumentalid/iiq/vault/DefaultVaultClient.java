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
     * The authentication token
     */
    private final String token;
    /**
     * The Vault URL
     */
    private final String vaultUrl;

    /**
     * Constructs a new DefaultVaultClient
     * @param vaultUrl The URL of the Vault instance
     * @param token The token to use for authentication (optional)
     * @param sslConfig The SSL configuration
     * @param engineVersion The Vault engine version
     */
    public DefaultVaultClient(String vaultUrl, String token, SslConfig sslConfig, int engineVersion) {
        this.vaultUrl = vaultUrl;
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

        var vaultConfig = new VaultConfig()
                .address(vaultUrl)
                .sslConfig(sslConfig)
                .build();

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
        var vaultConfig = new VaultConfig()
                .address(vaultUrl)
                .sslConfig(sslConfig)
                .build();

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
        var vaultConfig = new VaultConfig()
                .address(vaultUrl)
                .sslConfig(sslConfig)
                .build();

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

        var vaultConfig = new VaultConfig()
                .address(vaultUrl)
                .token(token)
                .sslConfig(sslConfig)
                .build();

        var vault = Vault.create(vaultConfig, engineVersion);
        return vault.logical().read(path);
    }
}

