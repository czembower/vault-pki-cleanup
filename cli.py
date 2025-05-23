import argparse
import logging
import hvac
import sys
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from tqdm import tqdm
import requests

def configure_logging(verbose: bool):
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )

def get_vault_client(addr: str, token: str, verify: bool, namespace: str = None) -> hvac.Client:
    client = hvac.Client(
        url=addr,
        token=token,
        verify=verify,
        namespace=namespace
    )
    if not client.is_authenticated():
        logging.error("Vault authentication failed.")
        sys.exit(1)
    return client

def get_default_issuer_and_key(client: hvac.Client, mount: str):
    logging.debug("Fetching default issuer ID...")
    try:
        resp = read_issuer(client=client, mount=mount, issuer_id="default")
        if resp is not None:
            default_issuer_id = resp['issuer_id']
            default_key_id = resp['key_id']
            logging.info(f"Default issuer ID/Key: {default_issuer_id}/{default_key_id}")
            return default_issuer_id, default_key_id
        else:
            return None, None
    except Exception as e:
        logging.error(f"Error fetching default issuer/key: {e}")
        sys.exit(1)

def list_issuers(client: hvac.Client, mount: str):
    try:
        resp = client.secrets.pki.list_issuers(mount_point=mount)
        return resp.get('data', {}).get('key_info', {}).keys()
    except Exception as e:
        if "None, on list" in str(e):
            logging.warning("No issuers found.")
            return []
        else:
            logging.error(f"Could not list issuers: {e}")
            sys.exit(1)
    
def read_issuer(client: hvac.Client, mount: str, issuer_id: str):
    try:
        resp = client.secrets.pki.read_issuer(issuer_id, mount_point=mount)
        return resp.get('data', {})
    except Exception as e:
        if "no default issuer currently configured" in str(e):
            return None
        else:
            logging.error(f"Could not read issuer: {e}")
            sys.exit(1)

def list_keys(client: hvac.Client, mount: str):
    try:
        path = f"/v1/{mount}/keys?list=true"
        resp = client.adapter.request("GET", path)
        return resp.get("data", {}).get("keys", [])
    except Exception as e:
        logging.error(f"Could not list keys: {e}")
        sys.exit(1)

def delete_issuer(client: hvac.Client, mount: str, issuer_id: str):
    try:
        client.secrets.pki.delete_issuer(issuer_id, mount_point=mount)
        logging.info(f"Deleted issuer: {issuer_id}")
    except Exception as e:
        logging.error(f"Failed to delete issuer {issuer_id}: {e}")
        sys.exit(1)

def delete_key(client: hvac.Client, mount: str, key_id: str):
    try:
        path = f"/v1/{mount}/key/{key_id}"
        client.adapter.request("DELETE", path)
    except Exception as e:
        logging.error(f"Failed to delete key {key_id}: {e}")
        sys.exit(1)

def cleanup_non_default_issuers_and_keys(client: hvac.Client, mount: str, dry_run: bool, pause_duration: float):
    default_issuer_id, default_key_id = get_default_issuer_and_key(client, mount)
    if default_issuer_id is None or default_key_id is None:
        logging.warning("No default issuer/key configured")
        input("Press any key to continue deleting ALL ISSUERS AND KEYS....(cntrl-c to cancel)")
    issuer_ids = list_issuers(client, mount)
    key_ids = list_keys(client, mount)

    for issuer_id in issuer_ids:
        if issuer_id != default_issuer_id:
            if dry_run:
                logging.info(f"[Dry-run] Would delete issuer: {issuer_id}")
            else:
                logging.info(f"Deleting issuer: {issuer_id}")
                delete_issuer(client, mount, issuer_id)
                if pause_duration > 0:
                    time.sleep(pause_duration)

    for key_id in key_ids:
        if key_id != default_key_id:
            if dry_run:
                logging.info(f"[Dry-run] Would delete key: {key_id}")
            else:
                logging.info(f"Deleting key: {key_id}")
                delete_key(client, mount, key_id)
                if pause_duration > 0:
                    time.sleep(pause_duration)

def cleanup_orphaned_keys(client: hvac.Client, mount: str, dry_run: bool, pause_duration: float):
    issuer_ids = list_issuers(client, mount)
    key_ids = list_keys(client, mount)
    keeper_keys=[]

    for issuer in issuer_ids:
        resp = read_issuer(client, mount, issuer)
        corresponding_key = resp["key_id"]
        if corresponding_key != "":
            logging.debug(f"Found issuer and corresponding key: {issuer}/{corresponding_key}")
            keeper_keys.append(corresponding_key)
    logging.info(f"Found {len(keeper_keys)} keys with corresponding issuers")

    deleted_keys = []
    if len(key_ids)-len(keeper_keys) > 0:
        logging.info(f"{get_prefix(dry_run)}Deleting {len(key_ids)-len(keeper_keys)} orphan keys from mount {mount}")

        for key_id in tqdm(key_ids, desc="Deleting keys", unit="key_id", dynamic_ncols=True):
            if key_id not in keeper_keys:
                if dry_run:
                    logging.debug(f"{get_prefix(dry_run)}Would delete orphaned key: {key_id}")
                else:
                    delete_key(client, mount, key_id)
                    deleted_keys.append(key_id)
                    if pause_duration > 0:
                        time.sleep(pause_duration)
    else:
        logging.info("No orphan keys to delete")

    logging.info(f"{get_prefix(dry_run)}Deleted {len(deleted_keys)} keys")

def list_certificates(client: hvac.Client, mount: str):
    try:
        resp = client.secrets.pki.list_certificates(mount_point=mount)
        return resp.get("data", {}).get("keys", [])
    except Exception as e:
        logging.error(f"Could not list certificates: {e}")
        sys.exit(1)

def read_certificate(client: hvac.Client, mount: str, serial: str):
    try:
        resp = client.secrets.pki.read_certificate(mount_point=mount, serial=serial)
        cert_pem = resp["data"]["certificate"]
        parsed_cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
        return parsed_cert
    except Exception as e:
        logging.error(f"Could not read or parse certificate: {e}")

def parse_certificates(client: hvac.Client, mount: str):
    cert_list = list_certificates(client, mount)
    valid_certs = []
    expired_certs = []
    for serial in cert_list:
        parsed_cert = read_certificate(client, mount, serial)
        if datetime.now(timezone.utc) > parsed_cert.not_valid_after_utc:
            expired_certs.append(serial)
        else:
            valid_certs.append(serial)
        
    logging.info(f"Found {len(cert_list)} certificate(s): {len(valid_certs)} valid / {len(expired_certs)} expired")
    return valid_certs, expired_certs

def get_mount_uuid(client: hvac.Client, mount: str):
    try:
        path = f"/v1/sys/mounts/{mount}"
        resp = client.adapter.request("GET", path)
        mount_uuid = resp.get("data", {}).get("uuid")
        return mount_uuid
    except Exception as e:
        logging.error(f"Failed to read mount UUID for {mount}: {e}")
        sys.exit(1)

def list_leases(client: hvac.Client, prefix: str):
    try:
        resp = client.sys.list_leases(prefix=prefix)
        leases = resp.get("data", {}).get("keys", [])
        return leases
    except Exception as e:
        logging.error(f"Failed to list leases: {e}")
        sys.exit(1)

def walk_leases(client: hvac.Client, prefix: str, lease_list: list[str]):
    logging.info(f"Inspecting leases at {prefix}")
    try:
        resp = list_leases(client, prefix)
        
        for item in resp:
            if item.endswith("/"):
                logging.debug(f"Prefix found at {prefix}: {item}")
                walk_leases(client, prefix+"/"+item[:-1], lease_list)
            else:
                logging.debug(f"Lease at {prefix}: {item}")
                lease_list.append(prefix+item)
        return lease_list
    except Exception as e:
        logging.error(f"Failed to walk leases: {e}")
        sys.exit(1)

def revoke_lease(client: hvac.Client, lease: str, force: bool = False):
    if force:
        try:
            logging.info(f"Force revoking lease {lease}")
            path = f"/v1/sys/leases/revoke-force/{lease}"
            resp = client.adapter.request("POST", path)
            return
        except Exception as e:
            logging.error(f"Failed to force-revoke lease {lease}: {e}")
            sys.exit(1)
    else:
        try:
            logging.info(f"Revoking lease {lease}")
            resp = client.sys.revoke_lease(lease)
        except Exception as e:
            logging.error(f"Failed to delete lease {lease}: {e}")
            sys.exit(1)

def tidy_leases(client: hvac.Client, dry_run: bool):
    if dry_run:
        logging.info(f"{get_prefix(dry_run)}Would tidy leases")
        return
    else:
        try:
            logging.info("Tidying leases")
            path = f"/v1/sys/leases/tidy"
            resp = client.adapter.request("POST", path)
            return
        except Exception as e:
            logging.error(f"Failed to tidy leases: {e}")
            sys.exit(1)

def cleanup_leases(client: hvac.Client, mount: str, dry_run: bool, pause_duration: float):
    leases = walk_leases(client, mount, [])
    logging.info(f"Found {len(leases)} leases to delete")

    for lease in leases:
        if dry_run:
            logging.info(f"{get_prefix(dry_run)}Would revoke lease: {lease}")
        else:
            revoke_lease(client, lease, force=False)
            if pause_duration > 0:
                time.sleep(pause_duration)

    tidy_leases(client, dry_run)

def delete_cert_with_raw(raw_client: hvac.Client, mount_uuid: str, cert: str, pause_duration: float):
    try:
        cert_path = cert.replace(":", "-")
        path = f"/v1/sys/raw/logical/{mount_uuid}/certs/{cert_path}"
        raw_client.adapter.request("DELETE", path)
        logging.debug(f"Deleted certificate {cert}")
        time.sleep(pause_duration)
    except Exception as e:
        logging.error(f"Failed to delete certificate from raw interface (is it enabled?): {e}")
        sys.exit(1)

def delete_certificates(client: hvac.Client, raw_client: hvac.Client, mount: str, dry_run: bool, pause_duration: float, expired_only: bool):
    valid_certs, expired_certs = parse_certificates(client, mount)
    mount_uuid = get_mount_uuid(client, mount)
    deleted_certs = []

    if expired_only:
        if len(expired_certs) == 0:
            logging.info("No expired certificates to delete")
        else:
            logging.info(f"{get_prefix(dry_run)}Deleting {len(expired_certs)} expired certificate(s) from mount {mount} ({mount_uuid})")
            for cert in tqdm(expired_certs, desc="Deleting certs", unit="cert", dynamic_ncols=True):
                if dry_run:
                    logging.debug(f"{get_prefix(dry_run)}Would delete certificate: {cert}")
                else:
                    delete_cert_with_raw(raw_client, mount_uuid, cert, pause_duration)
                    deleted_certs.append(cert)
    else:
        all_certs = valid_certs + expired_certs
        if len(all_certs) == 0:
            logging.info("No certificates to delete")
        else:
            logging.info(f"{get_prefix(dry_run)}Deleting {len(all_certs)} certificate(s) from mount {mount} ({mount_uuid})")
            for cert in tqdm(all_certs, desc="Deleting certs", unit="cert", dynamic_ncols=True):
                if dry_run:
                    logging.debug(f"[Dry-run] Would delete certificate: {cert}")
                else:
                    delete_cert_with_raw(raw_client, mount_uuid, cert, pause_duration)
                    deleted_certs.append(cert)

    logging.info(f"{get_prefix(dry_run)}Deleted {len(deleted_certs)} certificates")

def get_prefix(dry_run: bool):
    if dry_run:
        return "[DRY-RUN] "
    else:
        return ""
    
def self_confidence(vault_addr: str, insecure: bool):
    logging.info("Running self-confidence test...")
    iter = 1
    for i in tqdm(range(iter), desc="Testing", unit="iter", dynamic_ncols=True):
        try:
            resp = requests.get(url=vault_addr+"/v1/sys/leader", verify=not insecure)
            if resp.json()['is_self'] == False:
                logging.error("Self-confidence test failed: not self")
                return False
            time.sleep(.25)
        except Exception as e:
            logging.error(f"Self-confidence test failed: {e}")
            return False
    return True

def resolve_addr(vault_addr: str, vault_token: str, insecure: bool):
    headers = {'Content-Type': 'application/json',
           'X-Vault-Token': vault_token}

    try:
        resp = requests.get(url=vault_addr+"/v1/sys/leader", verify=not insecure)
        leader_address = resp.json()["leader_address"]
    except:
        logging.error("Vault unreachable")
        sys.exit(2)

    try:
        if requests.get(url=leader_address+"/v1/sys/health", verify=not insecure).status_code == 200:
            logging.info(f"Leader available: {leader_address}")
            if requests.get(url=leader_address+"/v1/sys/raw/logical?list=true", verify=not insecure, headers=headers).status_code == 200:
                logging.info(f"Raw interface available")
                return leader_address, True
    except:
        if self_confidence(vault_addr, insecure):
            logging.warning("Published leader address not reachable, but self-confidence test passed - proceeding")
            resp = requests.get(url=vault_addr+"/v1/sys/raw/logical?list=true", verify=not insecure, headers=headers)
            logging.info(resp)
            if resp.status_code == 200:
                logging.info(f"Raw interface available")
                return vault_addr, True
            
    return vault_addr, False

def list_db_path(client: hvac.Client, path: str, dry_run: bool, pause_duration: float):
    try:
        resp = client.adapter.request("GET", path+"?list=true")
        data = resp.get("data", {}).get("keys", [])
        for item in data:
            if item.endswith("/"):
                list_db_path(client, path+"/"+item[:-1], dry_run, pause_duration)
            else:
                delete_db_object(client, path+"/"+item, dry_run, pause_duration)
    except Exception as e:
        logging.error(f"Failed to list database path: {e}")
        sys.exit(1)

def delete_db_object(client: hvac.Client, path: str, dry_run: bool, pause_duration: float):
    if dry_run:
        logging.info(f"{get_prefix(dry_run)}Would delete database object at {path}")
        return
    else:
        logging.info(f"Deleting database object at {path}")
        try:
            logging.info(f"Deleting database object at {path}")
            resp = client.adapter.request("DELETE", path)
            logging.info(resp)
            time.sleep(pause_duration)
        except Exception as e:
            logging.error(f"Failed to delete database path: {e}")
            sys.exit(1)
            time.sleep(pause_duration)

def walk_db(client: hvac.Client, raw_client: hvac.Client, mount: str, dry_run: bool, pause_duration: float):
    logging.info(f"Walking database at {mount}")
    mount_uuid = get_mount_uuid(client, mount)
    logging.info(f"Mount UUID: {mount_uuid}")
    path = f"/v1/sys/raw/logical/{mount_uuid}"
    list_db_path(raw_client, path, dry_run, pause_duration)

def main():
    parser = argparse.ArgumentParser(description="Clean up orphaned PKI keys, non-default issuers, and expired certificates in Vault. Certificate deletion requires Vault's raw storage interface to be enabled.")
    parser.add_argument("--vault-addr", required=True, help="Vault server address (e.g. https://vault.example.com:8200)")
    parser.add_argument("--vault-token", required=True, help="Vault token with sufficient privileges to list and delete PKI engine issuers and keys, and access to the `sys/raw` interface if deleting certificates.")
    parser.add_argument("--mount", required=True, default="pki", help="PKI secrets engine mount path (default: 'pki')")
    parser.add_argument("--vault-namespace", default=None, help="Vault namespace (optional)")
    parser.add_argument("--mode", choices=["orphan-keys", "non-default-keys", "expired-certs", "all-certs", "leases", "walk-db"], default="orphan-keys", help="Sets which resources should be targeted for deletion. Defaults to `orphan-keys`")
    parser.add_argument("--pause-duration", type=float, default=0, help="Pause duration in seconds between deletions (default: 0)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (insecure)")
    parser.add_argument("--dry-run", action="store_true", help="Preview actions without deleting anything")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()
    configure_logging(args.verbose)

    if args.insecure:
        urllib3.disable_warnings(category=InsecureRequestWarning)
        logging.warning("TLS certificate verification is disabled (--insecure).")

    vault_address, raw_interface = resolve_addr(args.vault_addr, args.vault_token, args.insecure)
    client = get_vault_client(vault_address, args.vault_token, verify=not args.insecure, namespace=args.vault_namespace)

    if args.mode == "non-default-keys":
        cleanup_non_default_issuers_and_keys(client, args.mount, args.dry_run, args.pause_duration)
    elif args.mode == "orphan-keys":
        cleanup_orphaned_keys(client, args.mount, args.dry_run, args.pause_duration)
    elif args.mode == "expired-certs":
        if not raw_interface:
            logging.error("Certificate operations prohibited without raw interface access")
            sys.exit(1)
        raw_client = get_vault_client(vault_address, args.vault_token, verify=not args.insecure)
        delete_certificates(client, raw_client, args.mount, args.dry_run, args.pause_duration, expired_only=True)
    elif args.mode == "all-certs":
        if not raw_interface:
            logging.error("Certificate operations prohibited without raw interface access")
            sys.exit(1)
        raw_client = get_vault_client(vault_address, args.vault_token, verify=not args.insecure)
        delete_certificates(client, raw_client, args.mount, args.dry_run, args.pause_duration, expired_only=False)
    elif args.mode == "leases":
        cleanup_leases(client, args.mount, args.dry_run, args.pause_duration)
    elif args.mode == "walk-db":
        if not raw_interface:
            logging.error("Database operations prohibited without raw interface access")
            sys.exit(1)
        raw_client = get_vault_client(vault_address, args.vault_token, verify=not args.insecure)
        walk_db(client, raw_client, args.mount, dry_run=args.dry_run, pause_duration=args.pause_duration)
    else:
        logging.error("unknown mode -- see help menu")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
