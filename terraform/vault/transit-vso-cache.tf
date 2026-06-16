# Transit secrets engine for VSO client cache encryption
resource "vault_mount" "transit" {
  path        = "transit"
  type        = "transit"
  description = "Transit secrets engine for encryption as a service"
}

# Transit key for VSO client cache encryption
resource "vault_transit_secret_backend_key" "vso_client_cache" {
  backend          = vault_mount.transit.path
  name             = "vso-client-cache"
  deletion_allowed = true
}

# Policy for VSO to encrypt/decrypt client cache
resource "vault_policy" "vso_cache_encryption" {
  name = "vso-cache-encryption"

  policy = <<EOT
# Allow encryption of VSO client cache
path "${vault_mount.transit.path}/encrypt/${vault_transit_secret_backend_key.vso_client_cache.name}" {
  capabilities = ["create", "update"]
}

# Allow decryption of VSO client cache
path "${vault_mount.transit.path}/decrypt/${vault_transit_secret_backend_key.vso_client_cache.name}" {
  capabilities = ["create", "update"]
}
EOT
}