# -*- coding: utf-8 -*-
"""
cloud_update.py — Cloud: CTUpdate(mpk, ct_T, tk_{T->T'}) -> ct_{T'}

The cloud only holds mpk, ciphertext records and the update keys uploaded by data owners.
It never sees msk, E_T, user keys, DEKs or plaintext. C_AES is copied unchanged into the new
version; only the ABE part and the policy change.

Used by the Lambda handler (app.py) and as a local CLI:
  python cloud_update.py --store store/ --object-id <ID> [--base-version N]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Dict, Optional

from abe_core import CTUpdate, deserialize_any, load_public, serialize_any
from object_store import MPK_KEY, make_store, record_key, update_key_key


def apply_update(store, object_id: str, base_version: Optional[int] = None,
                 keep_history: bool = False) -> Dict[str, Any]:
    """
    keep_history=False (default, as in the paper): ct_{T'} replaces ct_T — vN and the consumed tk are
    deleted, so users who only satisfy the old policy cannot keep reading vN from the cloud.
    keep_history=True keeps vN (useful for demos; weakens policy tightening).
    """
    t0 = time.perf_counter()
    group, _abe, _mpk = load_public(store.get_json(MPK_KEY))

    latest = store.latest_version(object_id)
    if base_version is None:
        base_version = latest
    if base_version < latest:
        # S3 events are at-least-once: a duplicate event for an already-applied key is a no-op.
        return {"operation": "ctupdate", "object_id": object_id, "status": "skipped",
                "reason": f"tk_v{base_version} is stale (latest is v{latest})"}
    if base_version != latest:
        raise ValueError(f"Update key targets v{base_version} but latest is v{latest}.")

    tk_blob = store.get_json(update_key_key(object_id, base_version))
    if tk_blob.get("object_id") != object_id or int(tk_blob.get("base_version", -1)) != base_version:
        raise ValueError("Update key metadata does not match the object/version.")

    record = store.get_record(object_id, base_version)
    CT = deserialize_any(group, record["ct_abe"])
    tk = deserialize_any(group, tk_blob["tk"])
    CT_new = CTUpdate(CT, tk)

    new_record = dict(record)  # c_aes unchanged: no re-encryption of the data
    new_record.update({
        "version": base_version + 1,
        "policy": CT_new["policy"],
        "ct_abe": serialize_any(group, CT_new),
        "ts": int(time.time()),
    })
    written = store.put_record(new_record)
    store.delete(update_key_key(object_id, base_version))
    if not keep_history:
        store.delete(record_key(object_id, base_version))
    return {"operation": "ctupdate", "status": "ok", "object_id": object_id, "old_version": base_version,
            "kept_old_version": keep_history,
            "new_version": base_version + 1, "mode": tk["type"], "target_subtree": tk["target_subtree"],
            "new_policy": CT_new["policy"], "written": written,
            "ms": round((time.perf_counter() - t0) * 1000, 1)}


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Cloud: apply an uploaded update key (CTUpdate)")
    ap.add_argument("--store", required=True, help="directory or s3://bucket/prefix")
    ap.add_argument("--object-id", required=True)
    ap.add_argument("--base-version", type=int, default=None)
    ap.add_argument("--keep-history", action="store_true",
                    help="Keep the previous ciphertext version (demo only; default replaces it)")
    args = ap.parse_args(argv)
    try:
        res = apply_update(make_store(args.store), args.object_id, args.base_version, args.keep_history)
    except (ValueError, FileNotFoundError, FileExistsError, KeyError) as e:
        print(f"[cloud] error: {e}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(res, ensure_ascii=False))


if __name__ == "__main__":
    main()
