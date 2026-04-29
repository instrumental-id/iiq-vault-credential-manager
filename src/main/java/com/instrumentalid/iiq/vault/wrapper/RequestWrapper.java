package com.instrumentalid.iiq.vault.wrapper;

import java.lang.reflect.Method;
import java.util.Map;

import sailpoint.pam.credential.Request;

/**
 * For some reason, IIQ has the PAM {@link Request} class with its 'get' method at 
 * package visibility. This class wraps the Request object, using reflection to access
 * the methods that are not normally accessible to non-SailPoint code.
 */
public class RequestWrapper {
    /**
     * The name of the getRequestMap method in the Request class
     */
    private static final String GET_REQUEST_MAP = "getRequestMap";

    /**
     * The underlying request
     */
    private final Request request;
    
    /**
     * Constructs a new RequestWrapper around a PAM Request object.
     * 
     * @param request The PAM Request object to wrap
     */
    public RequestWrapper(Request request) {
        this.request = request;
    }

    /**
     * Retrieves the value associated with the specified key from the underlying Request.
     * If the key doesn't exist, returns null.
     * 
     * @param key The key whose associated value is to be returned
     * @return The value associated with the specified key, or null if the key doesn't exist
     */
    public Object get(String key) {
        return this.get(key, null);
    }

    /**
     * Retrieves the value associated with the specified key from the underlying Request.
     * If the key doesn't exist, returns the specified default value.
     * 
     * @param <T> The expected return type
     * @param key The key whose associated value is to be returned
     * @param defaultValue The default value to return if the key doesn't exist
     * @return The value associated with the key, or defaultValue if the key doesn't exist
     * @throws RuntimeException If an error occurs while invoking the get method
     */
    @SuppressWarnings("unchecked")
    public <T> T get(String key, T defaultValue) {
        try {
            Method getMethod = this.request.getClass().getDeclaredMethod("get", String.class, Object.class);
            getMethod.setAccessible(true);
            return (T) getMethod.invoke(this.request, key, defaultValue);
        } catch(Exception e) {
            throw new RuntimeException("Error invoking get method", e);
        }
    }

    /**
     * Gets the value of the specified key as a boolean from the underlying request. If
     * the value does not exist, or is an empty string, then the default value will be
     * returned. Otherwise, the value will be parsed via {@link Boolean#parseBoolean(String)}
     * 
     * @param key The key whose associated value is to be returned
     * @param defaultValue The default value to return if the key doesn't exist or is empty
     * @return The boolean value associated with the specified key, or defaultValue if the key doesn't exist or is empty
     */
    public boolean getBoolean(String key, boolean defaultValue) {
        String value = getString(key);
        if (value == null || value.isEmpty()) {
            return defaultValue;
        } else {
            return Boolean.parseBoolean(value);
        }
    }

    /**
     * Gets the String value associated with the specified key from the underlying Request.
     * If the value is not a String, its {@link Object#toString()} method will be invoked. 
     * If the value is null, this method also returns null.
     * 
     * @param key The key whose associated value is to be returned
     * @return The string value associated with the specified key, or null if the key doesn't exist
     */
    public String getString(String key) {
        Object whatever = get(key, null);
        if (whatever == null) {
            return null;
        } else {
            return String.valueOf(whatever);
        }
    }

    /**
     * Returns the underlying Request object as a Map. Used for debugging purposes.
     *
     * @return The underlying Request object as a Map
     */
    @SuppressWarnings({"unchecked", "unused"})
    public Map<String, Object> getRequestMap() {
        try {
            Method getRequestMapMethod = Request.class.getDeclaredMethod(GET_REQUEST_MAP);
            getRequestMapMethod.setAccessible(true);
            return (Map<String, Object>) getRequestMapMethod.invoke(this.request);
        } catch (Exception e) {
            throw new RuntimeException("Error invoking getRequestMap method", e);
        }
    }
}
