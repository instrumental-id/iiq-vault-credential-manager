package com.instrumentalid.iiq.vault.wrapper;

import java.lang.reflect.Constructor;
import java.util.Map;

import sailpoint.pam.credential.Response;

/**
 * This class provides a utility method to create a Response object from a Map.
 * 
 * The Response class is part of the sailpoint.pam.credential package.
 * The constructor of the Response class is package-private, so we need 
 * to use reflection to access it.
 */
public class Responses {

    /**
     * Creates a Response object from a Map of String key-value pairs.
     * 
     * @param values A Map containing the key-value pairs to be used to create the Response object
     * @return A new Response object created from the provided Map
     */
    public static Response fromMap(Map<String, String> values) {
        try {
            Constructor<Response> constructor = Response.class.getDeclaredConstructor(Map.class);
            constructor.setAccessible(true);;
            return constructor.newInstance(values);
        } catch (Exception e) {
            throw new RuntimeException("Error creating Response", e);
        }
    }
}
