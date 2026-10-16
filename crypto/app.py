# -*- coding: utf-8 -*-
"""
app.py — AWS Lambda entry point (cloud role, scheme A: owner encrypts locally, cloud updates).

Trigger: S3 ObjectCreated on   [<prefix>/]updates/<object_id>/tk_v<N>.json
Action : CTUpdate on [<prefix>/]objects/<object_id>/v<N>.json -> v<N+1>.json
         (vN and the tk are then deleted unless env KEEP_HISTORY=1)

Also accepts a direct invocation:
  {"action": "ctupdate", "bucket": "...", "prefix": "", "object_id": "...", "base_version": 1}

IAM for the function role (least privilege):
  s3:GetObject on config/*, objects/*, updates/*
  s3:PutObject on objects/*
  s3:DeleteObject on objects/*, updates/*   (replace old version, consume tk)
  (no access to msk, user keys or owner secrets — they are never in the bucket)
"""

from __future__ import annotations

import json
import logging
import os
import site
import urllib.parse
from typing import Any, Dict, List

# Charm is installed with --prefix=/var/task (see Dockerfile). The Lambda runtime does not always
# honour the image's PYTHONPATH, so register that site dir explicitly (also processes .pth/eggs).
_CHARM_SITE = "/var/task/lib/python3.10/site-packages"
if os.path.isdir(_CHARM_SITE):
    site.addsitedir(_CHARM_SITE)

from cloud_update import apply_update  # noqa: E402
from object_store import UPDATE_KEY_RE, S3Store  # noqa: E402

log = logging.getLogger()
log.setLevel(logging.INFO)

_s3 = None
KEEP_HISTORY = os.environ.get("KEEP_HISTORY", "0") == "1"


def _client():
    global _s3
    if _s3 is None:
        import boto3
        _s3 = boto3.client("s3")
    return _s3


def _from_s3_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    bucket = rec["s3"]["bucket"]["name"]
    key = urllib.parse.unquote_plus(rec["s3"]["object"]["key"])
    m = UPDATE_KEY_RE.search(key)
    if not m:
        return {"skipped": key, "reason": "not an update key"}
    prefix = key[: m.start()]  # match starts at the "/" before "updates/" (or at 0 without prefix)
    store = S3Store(bucket, prefix, client=_client())
    return apply_update(store, m.group("oid"), int(m.group("ver")), keep_history=KEEP_HISTORY)


def handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    if event.get("action") == "ctupdate":
        store = S3Store(event["bucket"], event.get("prefix", ""), client=_client())
        results.append(apply_update(store, event["object_id"], event.get("base_version"),
                                    keep_history=KEEP_HISTORY))
    else:
        for rec in event.get("Records", []):
            try:
                results.append(_from_s3_record(rec))
            except Exception as e:  # report per record; S3 retries are not useful for logic errors
                log.exception("CTUpdate failed")
                results.append({"error": str(e), "key": rec.get("s3", {}).get("object", {}).get("key")})
    for r in results:
        print(json.dumps(r, ensure_ascii=False))
    failed = [r for r in results if "error" in r]
    return {"status": "error" if failed else "ok", "results": results}
