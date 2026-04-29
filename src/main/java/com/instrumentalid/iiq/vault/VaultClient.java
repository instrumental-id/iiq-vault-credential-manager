package com.instrumentalid.iiq.vault;

import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.AuthResponse;
import io.github.jopenlibs.vault.response.LogicalResponse;

/**
 * Interface for Vault client operations
 *
 * The default implementation is {@link DefaultVaultClient}
 */
public interface VaultClient {
    /**
     * Authenticates with Vault using AppRole authentication
     * @param roleId The role ID
     * @param secretId The secret ID
     * @return The authentication response
     * @throws VaultException If an error occurs during authentication
     */
    AuthResponse loginByAppRole(String roleId, String secretId) throws VaultException;

    /**
     * Authenticates with Vault using JWT authentication
     * @param provider The JWT provider
     * @param role The JWT role
     * @param jwt The JWT token
     * @return The authentication response
     * @throws VaultException If an error occurs during authentication
     */
    AuthResponse loginByJwt(String provider, String role, String jwt) throws VaultException;

    /**
     * Authenticates with Vault using JWT authentication with a custom auth path
     * @param provider The JWT provider
     * @param role The JWT role
     * @param jwt The JWT token
     * @param authPath The custom auth path
     * @return The authentication response
     * @throws VaultException If an error occurs during authentication
     */
    AuthResponse loginByJwt(String provider, String role, String jwt, String authPath) throws VaultException;

    /**
     * Reads a secret from Vault
     * @param path The path to the secret
     * @return The logical response containing the secret data
     * @throws VaultException If an error occurs during the read
     */
    LogicalResponse read(String path) throws VaultException;
}

