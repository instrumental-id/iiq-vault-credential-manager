package com.instrumentalid.iiq.vault;

import com.instrumentalid.iiq.vault.dto.VaultResponse;
import io.github.jopenlibs.vault.VaultException;

public interface CredentialService {
    /**
     * Reads a Vault response from whatever source the implementation uses.
     * @return The Vault response
     * @throws VaultException If an error occurs while reading the Vault response
     */
    VaultResponse readVaultResponse() throws VaultException;
}
