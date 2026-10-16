# -*- coding: utf-8 -*-
"""
client_decrypt.py — Data user: Dec(mpk, sk_A, ct_T) -> M, run locally.

  1. download record (latest or a given version) from the cloud store
  2. K   = Dec(mpk, sk_A, CT_ABE)          (fails unless the key's attributes satisfy the policy)
  3. DEK = SHA-256(K);  M = AES-GCM-Dec(C_AES, DEK, AAD = object_id)

The attribute set comes from the private key itself; it cannot be claimed on the command line.

Example
  python client_decrypt.py --store store/ --sk keys/users/alice.json --object-id <ID> [--version 2] [--out file]
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag

from abe_core import deserialize_any, load_json, load_public, load_user_key
from hybrid import aes_gcm_decrypt, kdf_from_gt
from object_store import MPK_KEY, make_store


def client_decrypt(mpk_blob: Dict[str, Any], store, sk_path: str, object_id: str,
                   version: Optional[int] = None) -> bytes:
    group, abe, mpk = load_public(mpk_blob)
    sk = load_user_key(sk_path, group)
    record = store.get_record(object_id, version)
    if record.get("object_id") != object_id:
        raise ValueError("Record object_id mismatch.")
    CT = deserialize_any(group, record["ct_abe"])
    K = abe.decrypt(mpk, sk, CT)
    return aes_gcm_decrypt(record["c_aes"], kdf_from_gt(group, K), aad=object_id.encode("utf-8"))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Data user: download and decrypt")
    ap.add_argument("--mpk", default="", help="mpk.json (default: read config/mpk.json from --store)")
    ap.add_argument("--store", required=True)
    ap.add_argument("--sk", required=True, help="User secret key file from the Authority")
    ap.add_argument("--object-id", required=True)
    ap.add_argument("--version", type=int, default=None)
    ap.add_argument("--out", default="", help="Write plaintext bytes to this file instead of stdout")
    args = ap.parse_args(argv)

    store = make_store(args.store)
    mpk_blob = load_json(args.mpk) if args.mpk else store.get_json(MPK_KEY)
    try:
        pt = client_decrypt(mpk_blob, store, args.sk, args.object_id, args.version)
    except PermissionError as e:
        print(f"[user] access denied: {e}", file=sys.stderr)
        raise SystemExit(3)
    except InvalidTag:
        print("[user] integrity check failed: AES-GCM tag invalid (tampered record?)", file=sys.stderr)
        raise SystemExit(4)
    except (ValueError, FileNotFoundError, KeyError) as e:
        print(f"[user] error: {e}", file=sys.stderr)
        raise SystemExit(2)

    if args.out:
        with open(args.out, "wb") as f:
            f.write(pt)
    else:
        sys.stdout.buffer.write(pt)
        sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
