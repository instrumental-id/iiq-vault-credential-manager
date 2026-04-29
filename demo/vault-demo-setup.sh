# You should already be logged in, e.g., as a root token 

ROLE_NAME="myapp"
POLICY_NAME="approle-policy"

vault policy write "${POLICY_NAME}" - <<EOF
path "kv/data/iiq/*" {
  capabilities = ["read", "list"]
}

path "kv/metadata/iiq/*" {
  capabilities = ["list", "read"]
}

path "database/*" {
  capabilities = ["read", "list"]
}

path "database/*" {
  capabilities = ["create", "update", "delete"]
}


path "kv/data/iiq/*" {
  capabilities = ["create", "update", "delete"]
}

path "auth/approle/login" {
  capabilities = ["create", "update"]
}
EOF

vault write "auth/approle/role/${ROLE_NAME}" \
    token_policies="${POLICY_NAME}" \
    token_ttl=7d \
    token_max_ttl=7d \
    token_type=batch \
    secret_id_ttl=0 \
    secret_id_num_uses=0

vault kv put kv/iiq/test test=value