package com.instrumentalid.iiq.vault;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import com.instrumentalid.iiq.vault.dto.VaultOptions;
import com.instrumentalid.iiq.vault.dto.VaultResponse;
import com.instrumentalid.iiq.vault.wrapper.RequestWrapper;
import com.instrumentalid.iiq.vault.wrapper.Responses;
import com.instrumentalid.iiq.vault.wrapper.VaultCredentialManagerException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sailpoint.pam.credential.Configuration;
import sailpoint.pam.credential.CredentialManager;
import sailpoint.pam.credential.Request;
import sailpoint.pam.credential.Response;

import static com.instrumentalid.iiq.vault.Constants.VAULT_TYPE_DATABASE;
import static com.instrumentalid.iiq.vault.Constants.VAULT_TYPE_KV;

/**
 * VaultCredentialManager is an IIQ {@link CredentialManager} implementation that
 * retrieves a particular secret from an HCP Vault instance. It can use both
 * server and client certificates for authentication.
 *
 * The following configuration options are available:
 *
 * - url: The URL of the Vault instance
 * - token: A static token to use for authentication (optional)
 * - authType: The authentication type to use ('jwt' and 'appRole' support)
 * - roleId: The role ID to use for appRole authentication (required if authType is appRole)
 * - secretId: The secret ID to use for appRole authentication (required if authType is appRole)
 * - jwtPath: The path to the JWT token file (optional if authType is jwt)
 * - jwtRole: The role to use for JWT authentication (required if authType is jwt)
 * - jwt: The JWT token string (required if authType is jwt and jwtPath is not provided)
 * - jwtProvider: The JWT provider configured in Vault (required if authType is jwt)
 *
 * The following request parameters are available:
 *
 * - secretType: The type of secret to retrieve ('kv' or 'database', optional, defaults to 'kv')
 * - path: The path to the secret in the Vault (required)
 * - key: The key of the secret to retrieve (optional, defaults to "value")
 * - engineVersion: The version of the KV engine to use (optional, defaults to 2)
 *
 * The path must be set as the 'credentialAttributeName' of the request in the IIQ config.
 *
 * Note that 'kv' requests are usually engine version 2, while 'database' requests are
 * often engine version 1. Try switching the engine version if you get strange errors.
 *
 */
public class VaultCredentialManager implements CredentialManager {

    /**
     * The configuration object that contains the Vault URL and token.
     */
    private Configuration config;

    /**
     * The logger for this class.
     */
    private Log log;

    /**
     * The Vault client for performing Vault operations (injectable for testing)
     */
    private VaultClient vaultClient;

    /**
     * Constructs a new VaultCredentialManager with the specified configuration.
     * @param config The configuration object that contains the Vault URL and other config
     */
    public VaultCredentialManager(Configuration config) {
        this(config, null);
    }

    /**
     * Constructs a new VaultCredentialManager with the specified configuration and Vault client.
     * @param config The configuration object that contains the Vault URL and other config
     * @param vaultClient The Vault client to use (for testing)
     */
    public VaultCredentialManager(Configuration config, VaultClient vaultClient) {
        this.config = config;
        this.vaultClient = vaultClient;
        this.log = LogFactory.getLog(VaultCredentialManager.class);
    }

    /**
     * Retrieves a credential from the Vault.
     *
     * @param request The request object containing the parameters for the credential retrieval
     * @return A Response object containing the retrieved credential
     * @throws IllegalArgumentException If the inputs are invalid for the request
     * @throws RuntimeException If an error occurs while retrieving the credential
     */
    @Override
    public Response getCredential(Request request) throws VaultCredentialManagerException {
        try {
            // Wraps the request for easier parameter access
            var requestWrapper = new RequestWrapper(request);
            var options = parseOptions(request, requestWrapper);

            if (options.debug) {
                Map<String, Object> requestMap = requestWrapper.getRequestMap();
                log.info("VaultCredentialManager getCredential called with request: " + requestMap);
                if (log.isDebugEnabled()) {
                    if (this.config != null) {
                        Field configMap = Configuration.class.getDeclaredField("configMap");
                        configMap.setAccessible(true);
                        @SuppressWarnings("unchecked")
                        Map<String, Object> cfgMap = (Map<String, Object>) configMap.get(this.config);
                        log.debug("VaultCredentialManager configuration: " + cfgMap);
                        configMap.setAccessible(false);
                    }
                    log.debug("Parsed VaultOptions: " + options);
                }
            }

            CredentialService vaultService;
            if (options.type.equals(Constants.VAULT_TYPE_FILE)) {
                vaultService = new FileCredentialService(options, requestWrapper);
            } else {
                vaultService = new VaultCredentialService(this.config, requestWrapper, options, this.vaultClient);
            }

            VaultResponse response = vaultService.readVaultResponse();

            Map<String, String> responseMap = new HashMap<>();
            responseMap.put(options.path, response.getSecret());
            if (options.debug) {
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved secret for path '" + options.path + "': " + responseMap);
                } else {
                    log.info("Retrieved secret for path '" + options.path + "'");
                }
            }
            return Responses.fromMap(responseMap);
        } catch(RuntimeException e) {
            log.error(Constants.ERROR_GETTING_CREDENTIAL, e);
            throw e;
        } catch (Exception e) {
            log.error(Constants.ERROR_GETTING_CREDENTIAL, e);
            throw new VaultCredentialManagerException(Constants.ERROR_GETTING_CREDENTIAL, e);
        }
    }

    /**
     * Parses the options from the request and request wrapper.
     * @param request The original request from Sailpoint
     * @param requestWrapper The wrapped request for easier parameter access
     * @return The parsed Vault options
     */
    public VaultOptions parseOptions(Request request, RequestWrapper requestWrapper) {
        // Prepare the options for the Vault request
        var options = new VaultOptions();

        options.debug = requestWrapper.getBoolean("debug", false);

        // The path parameter refers to the Vault path where the secret is stored
        // Example: kv/myapp/database
        options.path = request.getAttributeName();
        if (options.path == null || options.path.isEmpty()) {
            throw new VaultCredentialManagerException(Constants.KV_PATH_REQUIRED);
        }

        options.type = (String) requestWrapper.get(Constants.TYPE);
        if (options.type == null || options.type.isEmpty()) {
            if (options.path.startsWith(VAULT_TYPE_DATABASE + "/")) {
                options.type = VAULT_TYPE_DATABASE;
            } else if (options.path.startsWith(VAULT_TYPE_KV + "/")) {
                options.type = VAULT_TYPE_KV;
            } else {
                log.warn("No secretType specified, defaulting to 'kv'");
                options.type = VAULT_TYPE_KV;
            }
        }

        // The key parameter specifies which field in the secret to retrieve
        // If not specified, defaults to "value"
        options.field = (String) requestWrapper.get(Constants.KEY);
        if (options.field == null || options.field.isEmpty()) {
            options.field = Constants.DEFAULT_VALUE_NAME;
        }

        String engineVersion = (String) requestWrapper.get(Constants.ENGINE_VERSION);
        if (engineVersion == null || engineVersion.isEmpty()) {
            engineVersion = "2";
        }
        options.engineVersion = Integer.parseInt(engineVersion);
        return options;
    }

    /**
     * Sets the Vault client for testing purposes
     * @param vaultClient The mock or test Vault client
     */
    protected void setVaultClient(VaultClient vaultClient) {
        this.vaultClient = vaultClient;
    }
}
