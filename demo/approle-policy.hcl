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