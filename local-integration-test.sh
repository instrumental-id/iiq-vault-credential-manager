#!/bin/bash

# This needs to set VAULT_TOKEN somehow. Implementation is up to you.
. ./local-vault-login.sh

URL="http://localhost:8200"
VAULT_PATH="database/static-creds/iiq_test_role"
VAULT_KV_SUBKEY="password"

./mvnw 'exec:java@integration-test' \
  -Dvault.url=$URL \
  -Dvault.token=${VAULT_TOKEN} \
  -Dvault.path=${VAULT_PATH} \
  -Dvault.engine.version=1 \
  -Pwith-key -Dvault.key.value=${VAULT_KV_SUBKEY}
