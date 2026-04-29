package com.instrumentalid.iiq.vault;

import picocli.CommandLine.Command;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.Callable;

import sailpoint.pam.credential.Configuration;
import sailpoint.pam.credential.Request;

@Command(
        name = "IntegrationTest",
        description = "Integration test for VaultCredentialManager",
        mixinStandardHelpOptions = true
)
public class IntegrationTest implements Callable<Integer> {

    @picocli.CommandLine.Option(names = {"-u", "--url"}, description = "Vault URL", required = true)
    private String url;

    @picocli.CommandLine.Option(names = {"-t", "--token"}, description = "Vault Token", required = true)
    private String token;

    @picocli.CommandLine.Option(names = {"-p", "--path"}, description = "Vault KV path", required = true)
    private String kvPath;

    @picocli.CommandLine.Option(names = {"-s", "--server-cert"}, description = "Path to the server certificate file", arity = "0..1")
    private Path serverCertFile;

    @picocli.CommandLine.Option(names = {"-c", "--client-key"}, description = "Path to the client key file", arity = "0..1")
    private Path clientKeyFile;

    @picocli.CommandLine.Option(names = {"-k", "--key"}, description = "Key to retrieve from within the Vault KV secret", arity = "0..1")
    private String key;

    @picocli.CommandLine.Option(names = {"-v", "--ssl-verify"}, description = "Enable SSL verification", defaultValue = "true", arity = "0..1")
    private boolean sslVerify = true;

    @picocli.CommandLine.Option(names = {"-e", "--engine-version"}, description = "Vault API engine version", defaultValue = "2", arity = "0..1")
    private String engineVersion;

    /**
     * Main method to run the integration test.
     * @param args Command line arguments
     */
    public static void main(String args[]) {
        String[] cleanedArgs = Arrays.stream(args)
                .filter(arg -> arg != null && !arg.equals("null"))
                .toArray(String[]::new);

        var result = new picocli.CommandLine(new IntegrationTest()).execute(cleanedArgs);
        if (result != 0) {
            System.exit(result);
        }
    }

    /**
     * Main method to run the integration test.
     */
    public Integer call() {
        if (url == null || token == null || kvPath == null) {
            System.err.println("URL, Token, and KV Path are required.");
            return 1;
        }

        if (url.equals("NOT_SET")) {
            System.err.println("URL is not set. Please provide a valid URL.");
            return 1;
        }

        try {
           testCredentialManager();
        } catch (Exception e) {
            System.err.println("Error during integration test: " + e.getMessage());
            return 1;
        }
        return 0;
    }
    

    /**
     * Test the VaultCredentialManager by retrieving a credential.
     * @throws Exception
     */
    public void testCredentialManager() throws Exception {
        var config = new Configuration();
        config.put(Constants.CONFIG_VAULT_URL, url);
        config.put(Constants.CONFIG_TOKEN, token);
        config.put(Constants.SERVER_CERT_PEM_FILE, serverCertFile != null ? serverCertFile.toString() : null);
        config.put(Constants.CLIENT_KEY_PEM_FILE, clientKeyFile != null ? clientKeyFile.toString() : null);
        config.put(Constants.ENGINE_VERSION, engineVersion);

        var manager = new VaultCredentialManager(config);

        var constructor = Request.class.getConstructor(Configuration.class);

        Request request = constructor.newInstance(config);
        request.setAttributeName(kvPath);

        if (key != null) {
            request.put(Constants.KEY, key);
        }

        var response = manager.getCredential(request);
        System.out.println("Retrieved Secret: " + response.getString(kvPath));
    }
}
