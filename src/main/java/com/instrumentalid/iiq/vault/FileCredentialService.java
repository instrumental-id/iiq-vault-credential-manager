package com.instrumentalid.iiq.vault;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.instrumentalid.iiq.vault.dto.VaultOptions;
import com.instrumentalid.iiq.vault.dto.VaultResponse;
import com.instrumentalid.iiq.vault.wrapper.RequestWrapper;
import io.github.jopenlibs.vault.VaultException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Implementation of CredentialService that reads credentials from a local file. This could
 * be used with Vault Agent, for example.
 */
public class FileCredentialService implements CredentialService {
    /**
     * The Vault options containing the file path
     */
    private final VaultOptions options;

    /**
     * The request wrapper to extract parameters
     */
    private final RequestWrapper requestWrapper;

    /**
     * Constructor
     * @param options The parsed Vault options
     * @param requestWrapper The request wrapper
     */
    public FileCredentialService(VaultOptions options, RequestWrapper requestWrapper) {
        this.options = options;
        this.requestWrapper = requestWrapper;
    }

    /**
     * Reads the Vault response from the local file
     * @return The Vault response
     * @throws VaultException If an error occurs while reading the file
     */
    @Override
    public VaultResponse readVaultResponse() throws VaultException {
        var filePath = Path.of(options.path);
        if (!Files.exists(filePath)) {
            return new VaultResponse(404, "Local file not found: " + options.path);
        }

        if (!Files.isReadable(filePath)) {
            return new VaultResponse(403, "Local file is not readable: " + options.path);
        }

        var field = requestWrapper.getString(Constants.KEY);

        try {
            String contents = Files.readString(filePath).trim();

            if (field == null || field.isEmpty()) {
                return new VaultResponse(contents);
            } else {
                if (contents.isEmpty()) {
                    return new VaultResponse("");
                } else {
                    // Assuming the file contains JSON data
                    var objectMapper = new ObjectMapper();
                    var jsonMap = objectMapper.readValue(contents, new TypeReference<Map<String, Object>>() {});

                    var value = jsonMap.get(field);
                    if (value != null) {
                        return new VaultResponse(value.toString());
                    } else {
                        return new VaultResponse(404, "Local file exists, but field '" + field + "' not found in file: " + options.path);
                    }
                }
            }
        } catch(IOException e) {
            throw new VaultException(e);
        }
    }
}
