package com.instrumentalid.iiq.vault.mocks;

import io.github.jopenlibs.vault.response.LogicalResponse;

import java.util.Map;

/**
 * Simple implementation of LogicalResponse for testing
 */
public class TestLogicalResponse extends LogicalResponse {
    private final Map<String, Object> data;

    public TestLogicalResponse(Map<String, Object> data) {
        this(data, 200);
    }

    public TestLogicalResponse(Map<String, Object> data, int httpStatus) {
        // Call parent constructor with dummy values
        super(new TestRestResponse(httpStatus, ""), 0, null);
        this.data = data;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Map getData() {
        return data;
    }
}
