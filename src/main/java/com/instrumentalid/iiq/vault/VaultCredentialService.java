package com.instrumentalid.iiq.vault;

import com.instrumentalid.iiq.vault.cache.DatabaseCredentialExtractor;
import com.instrumentalid.iiq.vault.cache.TokenCache;
import com.instrumentalid.iiq.vault.dto.VaultOptions;
import com.instrumentalid.iiq.vault.dto.VaultResponse;
import com.instrumentalid.iiq.vault.wrapper.RequestWrapper;
import com.instrumentalid.iiq.vault.wrapper.VaultCredentialManagerException;
import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.AuthResponse;
import io.github.jopenlibs.vault.response.LogicalResponse;
import lombok.Getter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import sailpoint.pam.credential.Configuration;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static com.instrumentalid.iiq.vault.Constants.*;

/**
 * Service class for handling Vault credential operations.
 */
@Getter
public class VaultCredentialService implements CredentialService {

    /**
     * The configuration object containing Vault settings.
     */
    private final Configuration config;
    /**
     * The logger for this class.
     */
    private final Log log;
    /**
     * The options corresponding to the Vault request.
     */
    private final VaultOptions options;
    /**
     * The request wrapper for accessing request parameters if needed.
     */
    private final RequestWrapper requestWrapper;
    /**
     * The Vault client for performing Vault operations (injectable for testing)
     */
    private VaultClient vaultClient;

    /**
     * Constructor for VaultCredentialService without a VaultClient (for production use)
     * @param config The configuration of the CredentialSource
     * @param requestWrapper The specific CredentialAssociation request
     * @param options The parsed Vault options for this request
     */
    public VaultCredentialService(Configuration config, RequestWrapper requestWrapper, VaultOptions options) {
        this(config, requestWrapper, options, null);
    }

    /**
     * Constructor for VaultCredentialService with a VaultClient (for testing)
     * @param config The configuration of the CredentialSource
     * @param requestWrapper The specific CredentialAssociation request
     * @param options The parsed Vault options for this request
     * @param vaultClient The Vault client to use (for testing)
     */
    public VaultCredentialService(Configuration config, RequestWrapper requestWrapper, VaultOptions options, VaultClient vaultClient) {
        this.config = config;
        this.requestWrapper = requestWrapper;
        this.options = options;
        this.vaultClient = vaultClient;
        this.log = LogFactory.getLog(VaultCredentialService.class);
    }

    /**
     * Authenticates to Vault using the AppRole authentication method.
     * @param sslConfig The SSL configuration
     * @param path The path to the secret
     * @param field The field within the secret
     * @param debug Whether to enable debug logging
     * @return The authentication token
     * @throws VaultException If an error occurs during authentication
     */
    private String authenticateAppRole(SslConfig sslConfig, String path, String field, boolean debug) throws VaultException {
        String roleId = this.config.getString(CONFIG_ROLE_ID);
        String secretId = this.config.getString(CONFIG_SECRET_ID);

        if (roleId == null || roleId.isEmpty()) {
            throw new IllegalArgumentException("roleId is required for appRole authentication");
        }
        if (secretId == null || secretId.isEmpty()) {
            throw new IllegalArgumentException("secretId is required for appRole authentication");
        }

        if (debug) {
            log.info("Authenticating to Vault using appRole with roleId: " + roleId);
        }

        VaultClient client = getOrCreateVaultClient(sslConfig);
        var authResponse = client.loginByAppRole(roleId, secretId);
        return extractAuthToken(path, field, authResponse, debug);
    }

    /**
     * Authenticates to Vault using JWT authentication method.
     * @param sslConfig The SSL configuration
     * @param path The path to the secret
     * @param field The field within the secret
     * @return The authentication token
     * @throws VaultException If an error occurs during authentication
     */
    private String authenticateJWT(SslConfig sslConfig, String path, String field) throws VaultException {
        String provider = this.config.getString(CONFIG_JWT_PROVIDER);
        String role = this.config.getString(CONFIG_JWT_ROLE);
        String jwt = this.config.getString(CONFIG_JWT);
        String authPath = this.config.getString(CONFIG_JWT_AUTH_PATH);

        VaultClient client = getOrCreateVaultClient(sslConfig);
        AuthResponse authResponse;
        if (authPath != null && !authPath.isEmpty()) {
            authResponse = client.loginByJwt(provider, role, jwt, authPath);
        } else {
            authResponse = client.loginByJwt(provider, role, jwt);
        }

        return extractAuthToken(path, field, authResponse, false);
    }

    /**
     * Builds the SSL configuration for the Vault client based on the request from SailPoint
     * @return The constructed SslConfig object
     * @throws VaultException If an error occurs while building the SSL configuration
     */
    protected SslConfig buildSSLConfig() throws VaultException {
        // Controls whether SSL certificate validation is performed
        // Set to false for self-signed certs in development environments
        var sslVerify = requestWrapper.getBoolean(Constants.SSL_VERIFY, true);

        // Begin SSL configuration for the Vault client
        // Various authentication methods are supported below
        var sslConfigBuilder = new SslConfig()
                .verify(sslVerify);

        if (options.debug) {
            log.info("Building SSL configuration with sslVerify=" + sslVerify);
        }

        // Client key can be used to authorize the client to the server
        var clientKeyPem = (String) requestWrapper.get(Constants.CLIENT_KEY_PEM_UTF8);
        if (clientKeyPem != null && !clientKeyPem.isEmpty()) {
            sslConfigBuilder.clientKeyPemUTF8(clientKeyPem);
        } else {
            // OR, client key can also be provided as a file path
            var clientKeyPemFile = (String) requestWrapper.get(Constants.CLIENT_KEY_PEM_FILE);
            if (clientKeyPemFile != null && !clientKeyPemFile.isEmpty()) {
                File file = new File(clientKeyPemFile);
                if (!file.exists()) {
                    throw new IllegalArgumentException(Constants.CLIENT_KEY_PEM_FILE_NOT_EXIST);
                }
                if (options.debug) {
                    log.info("Using client key PEM file: " + clientKeyPemFile);
                }
                sslConfigBuilder.clientKeyPemFile(file);
            }
        }

        // Server cert is used to authorize the server to the client
        var serverCertPemUTF = (String) requestWrapper.get(Constants.SERVER_CERT_PEM_UTF8);
        if (serverCertPemUTF != null && !serverCertPemUTF.isEmpty()) {
            sslConfigBuilder.pemUTF8(serverCertPemUTF);
        } else {
            var serverCertPem = (String) requestWrapper.get(Constants.SERVER_CERT_PEM_FILE);
            if (serverCertPem != null && !serverCertPem.isEmpty()) {
                File file = new File(serverCertPem);
                if (!file.exists()) {
                    throw new IllegalArgumentException(Constants.SERVER_CERT_PEM_FILE_NOT_EXIST);
                }

                if (options.debug) {
                    log.info("Using server cert PEM file: " + serverCertPem);
                }

                sslConfigBuilder.pemFile(file);
            }
        }

        return sslConfigBuilder.build();
    }

    /**
     * Extracts the authentication token from the Vault response and caches it.
     * @param path The path to the secret (so we can cache one token per secret, etc)
     * @param field The field within the secret (so we can cache one token per secret field, etc)
     * @param authResponse The authentication response from Vault
     * @return The extracted authentication token
     */
    private String extractAuthToken(String path, String field, AuthResponse authResponse, boolean debug) {
        if (authResponse.getRestResponse() != null) {
            if (authResponse.getRestResponse().getStatus() > 299) {
                String body = new String(authResponse.getRestResponse().getBody(), StandardCharsets.UTF_8);
                log.error("Error response from Vault: " + body);
                log.error("HTTP status code: " + authResponse.getRestResponse().getStatus());
                throw new VaultCredentialManagerException("HTTP error: " + authResponse.getRestResponse().getStatus() + " " + body);
            }
        }

        var duration = authResponse.getAuthLeaseDuration();
        var authToken = authResponse.getAuthClientToken();

        if (debug) {
            log.info("Obtained new auth token for " + path + " " + field + ", duration: " + duration);
        }

        // WARNING: logs the live token. Documented in the README under "Trace logging".
        if (log.isTraceEnabled()) {
            log.trace("Vault auth response for " + path + " " + field + ": token=" + authToken + ", duration=" + duration);
        }

        TokenCache.getInstance().putToken(path, field, authToken, duration);

        return authToken;
    }

    /**
     * Extracts the secret from the Vault response.
     * @param response The response from the Vault
     * @return The extracted secret, or an error response
     */
    protected VaultResponse extractSecret(LogicalResponse response) {
        if (response.getRestResponse() != null) {
            if (response.getRestResponse().getStatus() > 299) {
                String body = new String(response.getRestResponse().getBody(), StandardCharsets.UTF_8);

                log.error("Error response from Vault: " + body);
                log.error("HTTP status code: " + response.getRestResponse().getStatus());

                return new VaultResponse(response.getRestResponse().getStatus(), body);
            }
        }

        if (options.debug) {
            log.info("Successfully retrieved secret from Vault for path: " + options.path);
        }

        // WARNING: the next two trace statements log raw secret values. Documented in the README under "Trace logging".
        if (log.isTraceEnabled()) {
            log.trace("Raw Vault response data for path " + options.path + ": " + response.getData());
        }

        String value;

        if (options.type.equals(VAULT_TYPE_DATABASE)) {
            value = DatabaseCredentialExtractor.getInstance().extractCredential(response, options);
        } else {
            value = response.getData().get(options.field);
        }

        if (log.isTraceEnabled()) {
            log.trace("Extracted value for path " + options.path + " field '" + options.field + "': " + value);
        }

        if (value == null || value.isEmpty()) {
            log.error("Error from Vault: data field '" + options.field + "' not found in response (is the path " + options.path + " right?)");
            return new VaultResponse(-1, options.field + " not found in response");
        }

        return new VaultResponse(value);
    }

    /**
     * Fetches a secret from the Vault using the provided options and SSL configuration.
     * The secret is retrieved via logical read by path.
     *
     * @param sslConfig The SSL configuration for the Vault client
     * @return The Vault response containing the secret
     * @throws VaultException If an error occurs while fetching the secret
     */
    protected VaultResponse fetchSecret(SslConfig sslConfig) throws VaultException {
        VaultClient client = getOrCreateVaultClient(sslConfig);
        var response = client.read(options.path);
        return extractSecret(response);
    }

    /**
     * Gets or creates a VaultClient instance. Ordinarily, this will construct a new DefaultVaultClient,
     * but during testing, a specific testing instance can be injected to this class.
     *
     * @param sslConfig The SSL configuration
     * @return The VaultClient instance
     */
    private VaultClient getOrCreateVaultClient(SslConfig sslConfig) {
        if (this.vaultClient != null) {
            return this.vaultClient;
        }
        return new DefaultVaultClient(
                this.config.getString(Constants.CONFIG_VAULT_URL),
                options.token,
                sslConfig,
                options.engineVersion
        );
    }

    /**
     * Gets an authentication token for Vault access.
     *
     * There are three options:
     *
     * 1. If a static token is provided in the configuration, it is used directly.
     * 2. If a cached token exists for the given path and field, it is returned.
     * 3. If no token is found, authentication is performed based on the configured auth type.
     *
     * @param sslConfig The SSL configuration for the Vault client
     * @return The authentication token
     * @throws VaultException If an error occurs while retrieving the token
     */
    protected String getToken(SslConfig sslConfig) throws VaultException {
        String token = this.config.getString(Constants.CONFIG_TOKEN);
        if (token != null && !token.isEmpty()) {
            return token;
        }

        String path = options.path;
        String field = options.field;

        Optional<String> cachedToken = TokenCache.getInstance().getToken(path, field);
        if (cachedToken.isPresent()) {
            if (options.debug) {
                log.info("Using cached token for " + path + " " + field);
            }
            return cachedToken.get();
        }

        String authType = this.config.getString(Constants.CONFIG_AUTH_TYPE);
        if (authType == null) {
            throw new IllegalArgumentException("authType is required");
        }

        if (options.debug) {
            log.info("No cached token found for " + path + " " + field + ", performing authentication using type: " + authType);
        }

        // TODO: token renewal support
        // TODO: other auth types
        if (authType.equalsIgnoreCase(VAULT_AUTH_APP_ROLE)) {
            return authenticateAppRole(sslConfig, path, field, options.debug);
        } else if (authType.equalsIgnoreCase(VAULT_AUTH_JWT)) {
            return authenticateJWT(sslConfig, path, field);
        } else {
            throw new IllegalArgumentException("Unsupported authentication type: " + authType);
        }
    }

    /**
     * Reads a Vault credential field, utilizing caching for database credentials if available.
     *
     * @return The Vault response containing the requested credential
     * @throws VaultException If an error occurs while reading the credential
     */
    @Override
    public VaultResponse readVaultResponse() throws VaultException {
        VaultResponse response = null;

        // First, check the cache for database credentials that we've already retrieved
        if (options.type.equals(VAULT_TYPE_DATABASE)) {
            String cachedCredential = DatabaseCredentialExtractor.getInstance().getCachedCredential(options);
            if (cachedCredential != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Found cached credential for " + options.path + " " + options.field);
                }
                response = new VaultResponse(cachedCredential);
            }
        }

        // No cached credential, need to fetch from Vault
        if (response == null) {
            var sslConfig = buildSSLConfig();
            // TODO: Handle renewal?
            options.token = getToken(sslConfig);
            response = fetchSecret(sslConfig);

            if (response.getStatus() == 401 || response.getStatus() == 403) {
                // Token is expired, try to get a new token
                if (options.debug) {
                    log.info("Received authentication error " + response.getStatus() + " from Vault, trying to get a new token");
                }
                TokenCache.getInstance().invalidate(options.path, options.field, options.token);
                options.token = getToken(sslConfig);
                response = fetchSecret(sslConfig);

                if (response.getStatus() == 401 || response.getStatus() == 403) {
                    log.error("Authentication failed after token renewal attempt, status: " + response.getStatus());
                }
            }
        }

        return response;
    }

    /**
     * Sets the Vault client for testing purposes
     * @param vaultClient The mock or test Vault client
     */
    protected void setVaultClient(VaultClient vaultClient) {
        this.vaultClient = vaultClient;
    }

}
