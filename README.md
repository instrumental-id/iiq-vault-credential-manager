# HCP Vault Credential Provider for SailPoint IdentityIQ

This project implements an IdentityIQ (IIQ) Credential Provider for retrieving credentials from HashiCorp Vault. It allows IIQ to securely access credentials stored in Vault without having to store them directly in the IIQ system.

## Features

- Vault KV (key/value, version 1 & 2) and database secrets engine native support, plus anything that works with `vault read`
- SSL/TLS support with client key and server certificate validation
- Token caching for performance
- Token, JWT, and AppRole authentication method support (more to come)
- TLS settings, including custom server certificates and client keys
- Configurable debug logging for troubleshooting

## Building the Project

The project uses Maven for building. A Maven wrapper is included so you don't need to install Maven separately.

```bash
# Build the project
./mvnw clean package

# The JAR file will be created at:
# target/vault-credential-manager-1.0-SNAPSHOT.jar
```

## Integration Testing

An integration test utility is included to verify connectivity with your Vault server.

### Maven version

```bash
# Set up environment variables
export VAULT_TOKEN="your-vault-token"

# Run the integration test with Maven
./mvnw exec:java@integration-test \
  -Dvault.url=https://your.vault.server:8200 \
  -Dvault.token=${VAULT_TOKEN} \
  -Dvault.path=path/to/your/secret \
  -Dvault.engine.version=2 \
  -Pwith-key -Dvault.key.value=field_within_secret
```

The included `local-integration-test.sh` shows one way of running this test.

### JAR version

Alternatively, you can run the built JAR directly:

```bash
java -jar target/vault-credential-manager-1.0-SNAPSHOT.jar \
  --url https://your.vault.server:8200 \
  --token s.xxxxxxxxxxxxxxxx \
  --path secret/data/myapp/database \
  --engine-version 2 \
  --key password \
  --ssl-verify true
```

The following options are available:

- `--url` - Vault server URL
- `--token` - Authentication token
- `--path` - Path to the secret in Vault
- `--engine-version` - Vault KV engine version (1 or 2)
- `--key` - Key to extract from the Vault response (optional)
- `--ssl-verify` - Enable/disable SSL verification (default: true)
- `--server-cert` - Path to server certificate file (optional)
- `--client-key` - Path to client key file (optional)

## Installing in IdentityIQ

1. Build the project to create the JAR file. The output will be in `target/`.
2. Copy the JAR file to your IIQ installation's `WEB-INF/lib` directory. I usually exclude the version suffix so that it's easier to replace if the version changes.
3. Restart your IIQ application server.

## Configuration in IdentityIQ

Create/modify a Credential Configuration XML file to tell IIQ where to find your secrets.

### Example Configuration

See the example configuration provided with this project: [CredentialConfiguration.xml](config/CredentialConfiguration.xml). This is a SailPoint Configuration object that should be imported or merged into your environment.

### CredentialSource Attributes

These arguments tell the Credential Provider how to connect to Vault. Some of these values may be sensitive, such as the `secretId` or `token`.

**Authentication Parameters:**
- `authType` - Authentication type (currently only "appRole" is supported)
- `roleId` - AppRole role ID 
- `secretId` - AppRole secret ID
- `token` - Direct Vault token (alternative to AppRole)

**SSL/TLS Parameters:**
- `sslVerify` - Enable/disable SSL verification (default: true)
- `serverCertPemFile` - Path to server certificate file
- `serverCertPemUTF8` - Server certificate as UTF-8 string
- `clientKeyPemFile` - Path to client key file
- `clientKeyPemUTF8` - Client key as UTF-8 string

**Other Parameters:**
- `debug` - Enable debug logging (default: false). NOTE that this can log sensitive information.

### CredentialAssociation

These arguments tell the Credential Provider how to fetch a particular secret. These values should not be sensitive.

The `applicationName` and `attributeName` XML attributes point to the attribute _within the IIQ Application (connector)_ that will be replaced with the value fetched from Vault. When some field on an application is fed by a Credential Provider, the Application screen has the following message: "Credential Cycling is enabled for this application. Required field validation will not be performed."

The `credentialAttributeName` XML attribute specifies the path of your HCP Vault secret.

**Credential Association Attributes:**
- `engineVersion` - Vault API engine version (1 or 2)
- `key` - Key to extract from the Vault response (default: "value")

You will likely need to set a `key`, because Vault usually returns an object, not a value. The `key` specifies the field under `data` in the response from Vault. You can use the `vault read` CLI command with `-format=json` to determine what values are returned. For a database credential, it is probably `password`. If you don't specify a key, the default key is `value`.

An example extracted from an actual Vault database credential:

```json
"data": {
  "last_vault_rotation": "2025-03-27T17:17:54.965317229Z",
  "password": "z6MfMou6...",
  "rotation_period": 86400,
  "ttl": 73325,
  "username": "rotation_test"
}
```

KV secrets can contain arbitrary data field values.

#### Credentials with multiple fields

You can pull multiple data fields from the same Vault secret by creating multiple CredentialAssociation entries that point to the same `credentialAttributeName` but specify different `key` values. For _database_ type secrets, the Credential Provider will cache the response to avoid excessive API calls.

## Authentication to Vault

Currently, only AppRole authentication is supported. You will need to create an AppRole in Vault with appropriate policies to allow reading the desired secrets. For debugging purposes, you can also specify a `token` directly in your Credential Source config, but this is strongly discouraged in actual usage.

## Troubleshooting

- Check Vault server connectivity using the integration test utility.
- Verify the correct engine version (KV v1 vs KV v2 vs database secrets).
- Check IIQ logs for detailed error messages.
- Ensure the AppRole has the necessary permissions in Vault.
- As a last resort, set `debug` to true on the Credential Source. See below for cautions.

### Debug logging

Setting `debug` to true on either the CredentialSource or any CredentialAssociation will do more verbose logging at INFO level, which can help diagnose issues.

To enable even more verbose logging, **including sensitive values**, set the logger for `com.instrumentalid.iiq.vault` to DEBUG level in your log4j configuration.

If the logger is set to DEBUG level in addition to the `debug` flag, all configuration and input parameters, plus responses, will be logged. **These log messages will contain sensitive information, including AppRole authentication info and the retrieved secret.** It may be wise to route logs for this class to a separate file with restricted access. Ensure that the file is also not consumed by Splunk or other log aggregators.