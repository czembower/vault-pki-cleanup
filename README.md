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
- Smart leader resolution with raw interface verification (needed for certificate deletion)
- Self-confidence fallback if Vault’s advertised leader is unreachable

---

## Requirements

- Python 3.8+
- Vault PKI secrets engine (v1.9+ recommended)
- Permissions:
  - PKI read/delete access
  - Optional: `sys/raw` access for certificate deletion

---

## Installation

```bash
pip install -r requirements.txt
```

## Modes

```
orphan-keys       Deletes keys with no associated issuer (default)
non-default-keys  Deletes all issuers and keys except the current default
expired-certs     Deletes expired certificates (via raw storage interface)
all-certs         Deletes all certificates (via raw storage interface)
```

## Options

```
--vault-addr	    Vault server URL
--vault-token	    Token with sufficient privileges
--mount	            Path to the PKI engine (e.g., pki, pki_int)
--vault-namespace	Optional Vault namespace for Enterprise
--mode	            Operation mode (see table above)
--pause-duration	Optional sleep in seconds between deletions
--insecure	        Disable TLS verification (use with caution!)
--dry-run	        Preview changes without making modifications
--verbose	        Enable debug logging
```

## Vault Policy Requirements

```
path "pki_mount/*" {
  capabilities = ["read", "list", "delete"]
}
```

```
path "sys/raw/*" {
  capabilities = ["read", "list", "delete"]
}
```

### How It Works

- Uses the hvac API client for most Vault operations
- Uses direct HTTP requests for low-level sys/raw access
- Uses tqdm for smooth progress display
- Supports namespace headers and TLS verification toggling

### Warnings

- Always test with --dry-run before live deletion
- Certificate deletion uses raw storage — use with extreme caution
- Assumes only one "default" issuer and key should be retained (when run in `non-default` mode)
- Avoid running simultaneously on multiple Vault nodes