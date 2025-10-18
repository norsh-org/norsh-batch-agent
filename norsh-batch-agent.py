# Norsh ○ ●●
# Norsh Batch Signer
# Developed by Danthur Lice and contributors.
# Copyright © 2024-{current_year} Norsh. All rights reserved.
#
# Documentation: NTP-3: Cryptography and Hash Specification
# https://docs.norsh.org/ntp/ntp-3
#
# License
# This project is licensed under the Norsh Commons License (NCL-139), which prohibits commercial use without explicit authorization.
# Alternatively, this code may be used under the terms of the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0) license.
# See NCL-139 and [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) for more details.

import argparse
import json
import base64
import hashlib
import requests
import sys
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA3_384
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

# --- GLOBAL CONSTANTS AND CONFIGURATION ---
SYSTEM_NAME = "Norsh Batch Signer"
HEAD = (
    f"\nNorsh ○ ●●\n{SYSTEM_NAME}\nDeveloped by Danthur Lice and contributors.\n"
    f"Copyright © 2024-{{}} Norsh. All rights reserved.\n"
)

ENDPOINTS = {
    "PRODUCTION": "https://api.norsh.org",
    "SANDBOX": "https://sandbox.norsh.org"
}

DEFAULT_ENDPOINT = "PRODUCTION"
DEFAULT_NETWORK = "main"
PBKDF2_ITER = 65536
SALT_SIZE = 16
IV_SIZE = 16
KEYLEN = 32

# --- LOADERS ---

def load_encrypted_private_key(path, password: str):
    """
    Load an encrypted private key from a custom PEM format using PBKDF2 and AES-CBC.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if not l.startswith("-----")]
        raw = base64.b64decode("".join(lines))
        salt, iv, ciphertext = raw[:SALT_SIZE], raw[SALT_SIZE:SALT_SIZE+IV_SIZE], raw[SALT_SIZE+IV_SIZE:]
        key = PBKDF2(password, salt, dkLen=KEYLEN, count=PBKDF2_ITER, hmac_hash_module=SHA3_384)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        pad = decrypted[-1]
        if pad > 16:
            raise ValueError("> Invalid padding (wrong password or corrupted key file).")
        der = decrypted[:-pad]
        return serialization.load_der_private_key(der, password=None)
    except Exception as e:
        raise RuntimeError("> Failed to decrypt private key. Possible causes: wrong password, corrupted file, or invalid format.") from e

def load_private_key(path, password=None):
    """
    Load a private key from PEM file. Supports both encrypted and unencrypted keys.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
        return serialization.load_pem_private_key(data, password=password.encode() if password else None)
    except ValueError:
        if password:
            # Try custom encrypted format
            return load_encrypted_private_key(path, password)
        raise RuntimeError("> Invalid private key file or format not supported.")

# --- SIGNATURE LOGIC ---

def sha3_384(data: bytes) -> bytes:
    """
    Compute SHA3-384 hash of the input data.
    """
    return hashlib.sha3_384(data).digest()

def sign(privkey, preimage: str) -> str:
    """
    Sign the preimage string using ECDSA with SHA3-384.
    """
    digest = sha3_384(preimage.encode("utf-8"))
    sig = privkey.sign(digest, ec.ECDSA(hashes.SHA3_384()))
    return base64.b64encode(sig).decode()

def extract_values(obj):
    """
    Recursively extract all non-None values from a dict or list, as strings.
    """
    vals = []
    for k in sorted(obj.keys()):
        v = obj[k]
        if v is None:
            continue
        if isinstance(v, dict):
            vals.extend(extract_values(v))
        elif isinstance(v, list):
            for i in v:
                if i is not None:
                    vals.append(str(i))
        else:
            vals.append(str(v))
    return vals

def build_preimage(parameters, metadata, public_b64):
    """
    Build the preimage string for signing, using all values from parameters, metadata, and public key.
    """
    all_values = extract_values(parameters) + extract_values(metadata) + [public_b64]
    sorted_values = sorted(all_values, key=lambda x: str(x))
    return "|".join(sorted_values)

# --- MAIN ---

def main():
    year = datetime.now().year
    
    parser = argparse.ArgumentParser(description=SYSTEM_NAME, allow_abbrev=True)
    parser.add_argument("-k", "--key", required=True, help="Private key PEM (PKCS#8, encrypted or not)")
    parser.add_argument("-p", "--pwd", help="Password for private key (optional)")
    parser.add_argument("-j", "--json", required=True, help="Input JSON array file")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode (suppress banner)")
    parser.add_argument("-o", "--output", action="store_true", help="Show API response output (no effect if --nosend is used)")
    parser.add_argument("-n", "--network", default=DEFAULT_NETWORK, help="Network segment for API URL (default: main)")
    parser.add_argument("-e", "--endpoint", choices=["SANDBOX"], default=DEFAULT_ENDPOINT, help="Use SANDBOX endpoint (https://sandbox.norsh.org). If omitted, uses the default API endpoint (https://api.norsh.org).")
    parser.add_argument("-ns", "--nosend", action="store_true", help="Sign only, output signed payload without sending to API")
    args = parser.parse_args()

    if not args.silent:
        print(HEAD.format(year))

    # Build API URL based on endpoint and network
    base_url = ENDPOINTS[args.endpoint]
    api_url = f"{base_url}/{args.network}/v1/ucp"
    try:
        priv = load_private_key(args.key, args.pwd)
    except RuntimeError as err:
        print(f"> {str(err)}")
        sys.exit(1)

    pub = priv.public_key()
    pub_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b64 = base64.b64encode(pub_der).decode()

    try:
        with open(args.json, "r", encoding="utf-8") as f:
            batch = json.load(f)
    except Exception:
        print("> Failed to read or parse JSON input file.")
        sys.exit(1)

    signed = []
    for item in batch:
        params = item.get("parameters", {})
        meta = item.get("metadata", {})
        preimage = build_preimage(params, meta, pub_b64)
        signature = sign(priv, preimage)
        item["publicKey"] = pub_b64
        item["signature"] = signature
        signed.append(item)

    if args.nosend:
        print(json.dumps(signed))
        sys.exit(0)

    try:
        r = requests.post(api_url, json=signed, timeout=30)
        try:
            response = r.json()
        except Exception:
            print("> Error: Invalid JSON response from server.")
            sys.exit(1)
        if args.output:
            print(r.text)

        print(f"> Status: {r.status_code}")
        sys.exit(0)
    except requests.exceptions.Timeout:
        print("> Error: Connection timed out while contacting the API server.")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("> Error: Could not connect to the API server.")
        sys.exit(1)
    except Exception as err:
        print(f"> Unexpected error: {err}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("> Operation cancelled by user.")
