# -*- coding: utf-8 -*-
"""
owner_upkeygen.py — Data owner: UPKeyGen(mpk, E_T, T, T') -> tk_{T->T'}, run locally.

  1. read the current ciphertext record vN from the cloud store (public tree structure)
  2. load the owner's private E_T for vN
  3. detect which single gate changes (Attributes2Existing / Attributes2New) and build tk
  4. upload tk to updates/<object_id>/tk_vN.json   (in S3 this triggers the CTUpdate Lambda)
  5. store E_T for v(N+1) locally (adds the fresh s_t for Attributes2New)

Only tk leaves the owner's machine — never E_T.

Example
  python owner_upkeygen.py --store store/ --secrets-dir owner_secrets --object-id <ID> \
      --new-policy "(attA OR (2, attB, attC, attD))"
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional

from abe_core import (UPKeyGen, deserialize_any, load_json, load_public, serialize_any)
from object_store import MPK_KEY, FileStore, make_store, record_key, update_key_key
from owner_encrypt import save_E_T, secret_key_name


def owner_upkeygen(mpk_blob: Dict[str, Any], store, secrets: FileStore, object_id: str,
                   new_policy: str, base_version: Optional[int] = None, mode: Optional[str] = None,
                   target_subtree: Optional[str] = None, force: bool = False) -> Dict[str, Any]:
    group, abe, mpk = load_public(mpk_blob)
    if base_version is None:
        base_version = store.latest_version(object_id)
    record = store.get_record(object_id, base_version)
    if store.exists(record_key(object_id, base_version + 1)):
        raise FileExistsError(f"v{base_version + 1} already exists; update from the latest version instead.")
    tk_key = update_key_key(object_id, base_version)
    if store.exists(tk_key) and not force:
        raise FileExistsError(f"{tk_key} already exists (pending update). Use --force to replace it.")

    CT = deserialize_any(group, record["ct_abe"])
    E_T = deserialize_any(group, secrets.get_json(secret_key_name(object_id, base_version))["E_T"])

    tk, E_T_next = UPKeyGen(abe, mpk, E_T, CT["tree"], new_policy,
                            expect_mode=mode, expect_target=target_subtree)

    tk_blob = {"object_id": object_id, "base_version": base_version, "tk": serialize_any(group, tk)}
    save_E_T(secrets, group, object_id, base_version + 1, E_T_next)
    store.put_json(tk_key, tk_blob)
    return {"object_id": object_id, "base_version": base_version, "mode": tk["type"],
            "target_subtree": tk["target_subtree"], "new_subtree": tk.get("new_subtree"),
            "reissued_child_components": sorted(tk["tk_children"].keys()),
            "update_key": tk_key}


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Data owner: generate a policy update key")
    ap.add_argument("--mpk", default="", help="mpk.json (default: read config/mpk.json from --store)")
    ap.add_argument("--store", required=True)
    ap.add_argument("--secrets-dir", default="owner_secrets")
    ap.add_argument("--object-id", required=True)
    ap.add_argument("--new-policy", required=True)
    ap.add_argument("--version", type=int, default=None, help="Base version (default: latest)")
    ap.add_argument("--mode", choices=["Attributes2Existing", "Attributes2New"], default=None,
                    help="Optional: assert the detected update type")
    ap.add_argument("--target-subtree", default=None, help="Optional: assert the detected target gate")
    ap.add_argument("--force", action="store_true", help="Replace a pending (not yet applied) update key")
    args = ap.parse_args(argv)

    store = make_store(args.store)
    mpk_blob = load_json(args.mpk) if args.mpk else store.get_json(MPK_KEY)
    try:
        res = owner_upkeygen(mpk_blob, store, FileStore(args.secrets_dir), args.object_id, args.new_policy,
                             base_version=args.version, mode=args.mode,
                             target_subtree=args.target_subtree, force=args.force)
    except (ValueError, FileExistsError, FileNotFoundError, KeyError) as e:
        print(f"[owner] error: {e}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(res, ensure_ascii=False))


if __name__ == "__main__":
    main()
