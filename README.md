# Vault PKI Cleanup Utility

A command-line tool to clean up orphaned keys, non-default issuers, and expired (or all) certificates in a HashiCorp Vault PKI secrets engine. This tool is particularly useful in long-lived, automated, or even misconfigured environments where PKI data can accumulate over time.

---

## Features

- Deletes:
  - Orphaned keys (keys not tied to any active issuer)
  - Non-default issuers and keys
  - Expired certificates
  - All certificates (if needed)
- Supports dry-run mode to preview changes
- Leader resolution with raw interface verification (needed for certificate deletion)
- Self-confidence fallback if Vault’s advertised leader is unreachable directly

---

## Requirements

- Python 3.8+
- Vault cluster with PKI secrets engine
- Permissions:
  - PKI read/delete access
  - Optional: `sys/raw` access for certificate deletion

---

## Installation

```bash
pip install -r requirements.txt
```

## Example Usage

```shell
python3 cli.py \
  --vault-addr=https://localhost:8200 \
  --vault-namespace=myNamespace \
  --vault-token=$VAULT_TOKEN \
  --mount=pki_int \
  --pause-duration=.25 \
  --mode=expired-certs
```

## Modes

```
orphan-keys       Deletes keys with no associated issuer (default)
non-default-keys  Deletes all issuers and keys except the current default
expired-certs     Deletes expired certificates (via raw storage interface)
all-certs         Deletes all certificates (via raw storage interface)
leases            Deletes all leases associated with the target mount
walk-db           Deletes all resources under the target mount - USE WITH EXTREME CAUTION
```

## Options

```
--vault-addr      Vault server URL
--vault-token     Token with sufficient privileges
--mount           Path to the PKI engine (e.g., pki, pki_int)
--vault-namespace Optional Vault namespace for Enterprise
--mode            Operation mode (see table above)
--pause-duration  Optional sleep in seconds between deletions
--insecure        Disable TLS verification (use with caution!)
--dry-run         Preview changes without making modifications
--verbose         Enable debug logging
```

## Vault Policy Requirements

The policy used by this utility must grant access to `sys/raw` in the root
namespace, and therefore should be defined in the root namespace. The below
example policy grants access to the PKI engine `pki_int` in the root namespace.
If the target engine resides within a child namespace, authentication should
still occur in the root namespace, but the policy will need to provide access
to the child namespace endpoints at the paths below, prepended by the namespace
name or a "+". 

Root namespace policy example:
```
path "sys/mounts/*" {
  capabilities = ["read"]
}

path "pki_int/*" {
  capabilities = ["read", "list", "delete"]
}

path "sys/leases/*" {
  capabilities = ["update", "read", "list", "delete"]
}

path "sys/raw/*" {
  capabilities = ["read", "list", "delete", "sudo"]
}
```

Child namespace policy example:
```
path "+/sys/mounts/*" {
  capabilities = ["read"]
}

path "+/pki_int/*" {
  capabilities = ["read", "list", "delete"]
}

path "+/sys/leases/*" {
  capabilities = ["update", "read", "list", "delete"]
}

path "sys/raw/*" {
  capabilities = ["read", "list", "delete", "sudo"]
}
```

### How It Works

- Uses the hvac API client for most Vault operations
- Uses direct HTTP requests for low-level sys/raw access

### Warnings

- Always test with --dry-run before live deletion
- Certificate deletion uses raw storage interface (`sys/raw`) — use with extreme caution
- Assumes only one "default" issuer and key should be retained (when run in `non-default` mode)
- Avoid running simultaneously on multiple Vault nodes