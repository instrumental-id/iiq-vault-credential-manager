package com.instrumentalid.iiq.vault.wrapper;

public class VaultCredentialManagerException extends RuntimeException {
    public VaultCredentialManagerException(String message) {
        super(message);
    }

    public VaultCredentialManagerException(String message, Throwable cause) {
        super(message, cause);
    }
}
