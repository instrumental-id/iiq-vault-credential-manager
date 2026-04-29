package com.instrumentalid.iiq.vault.mocks;

import io.github.jopenlibs.vault.rest.RestResponse;

/**
 * Override the RestResponse for testing
 */
public class TestRestResponse extends RestResponse {
    public TestRestResponse(int statusCode, String body) {
        super(statusCode, "application/json", (body == null) ? new byte[0] : body.getBytes());
    }
}
