# -*- coding: utf-8 -*-
"""
owner_encrypt.py — Data owner: Enc(M, mpk, T) -> (ct_T, E_T), run locally.

  1. K  <- random GT element;  DEK = SHA-256(K)
  2. C_AES  = AES-256-GCM(M, DEK, AAD = object_id)
  3. (CT_ABE, E_T) = Enc(K, mpk, policy)
  4. upload {policy, C_AES, CT_ABE} to the cloud store as v1
  5. keep E_T in the owner's private secrets directory (never uploaded)

Example
  python owner_encrypt.py --mpk keys/mpk.json --store store/ --secrets-dir owner_secrets \
      --policy "(attA OR (attB AND attC))" --plaintext "hello world"
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from typing import Any, Dict, Optional

from charm.toolbox.pairinggroup import GT

from abe_core import SCHEME_ID, load_json, load_public, serialize_any
from hybrid import aes_gcm_encrypt, kdf_from_gt
from object_store import MPK_KEY, FileStore, make_store


def secret_key_name(object_id: str, version: int) -> str:
    return f"{object_id}/E_T_v{int(version)}.json"


def save_E_T(secrets: FileStore, group, object_id: str, version: int, E_T: Dict[str, Any]) -> None:
    secrets.put_json(secret_key_name(object_id, version),
                     {"object_id": object_id, "version": int(version), "E_T": serialize_any(group, E_T)})


def owner_encrypt(mpk_blob: Dict[str, Any], store, secrets: FileStore, plaintext: bytes,
                  policy: str, object_id: Optional[str] = None) -> Dict[str, Any]:
    t0 = time.perf_counter()
    group, abe, mpk = load_public(mpk_blob)

    object_id = object_id or str(uuid.uuid4())
    K = group.random(GT)
    c_aes = aes_gcm_encrypt(plaintext, kdf_from_gt(group, K), aad=object_id.encode("utf-8"))
    CT, E_T = abe.encrypt(K, mpk, policy)

    record = {
        "scheme": SCHEME_ID,
        "object_id": object_id,
        "version": 1,
        "policy": policy,
        "c_aes": c_aes,
        "ct_abe": serialize_any(group, CT),
        "ts": int(time.time()),
    }
    save_E_T(secrets, group, object_id, 1, E_T)   # owner-local first, then upload
    store.put_record(record)
    return {"object_id": object_id, "version": 1, "policy": policy,
            "ms": round((time.perf_counter() - t0) * 1000, 1)}


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Data owner: encrypt and upload")
    ap.add_argument("--mpk", default="", help="mpk.json (default: read config/mpk.json from --store)")
    ap.add_argument("--store", required=True, help="Cloud store: directory or s3://bucket/prefix")
    ap.add_argument("--secrets-dir", default="owner_secrets", help="Owner-private directory for E_T")
    ap.add_argument("--policy", required=True)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--plaintext")
    src.add_argument("--in-file")
    ap.add_argument("--object-id", default="", help="Optional object id (default: random UUID)")
    args = ap.parse_args(argv)

    store = make_store(args.store)
    mpk_blob = load_json(args.mpk) if args.mpk else store.get_json(MPK_KEY)
    data = args.plaintext.encode("utf-8") if args.plaintext is not None else open(args.in_file, "rb").read()
    try:
        res = owner_encrypt(mpk_blob, store, FileStore(args.secrets_dir), data, args.policy,
                            object_id=args.object_id or None)
    except (ValueError, FileExistsError) as e:
        print(f"[owner] error: {e}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(res, ensure_ascii=False))


if __name__ == "__main__":
    main()
