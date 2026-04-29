package com.instrumentalid.iiq.vault.dto;

import lombok.Getter;

@Getter
public class VaultResponse {
    private final String error;
    private final String secret;
    private final int status;

    public VaultResponse(int status, String error) {
        this.status = status;
        this.secret = null;
        this.error = error;
    }

    public VaultResponse(String secret) {
        this.status = 200;
        this.secret = secret;
        this.error = null;
    }
}
