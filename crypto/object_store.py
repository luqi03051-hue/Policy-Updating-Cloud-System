# -*- coding: utf-8 -*-
"""
object_store.py — the cloud-side store, as a local directory (PoC) or an S3 bucket.

Key layout (identical for both back-ends):
  config/mpk.json                      public parameters (no msk!)
  objects/<object_id>/v<N>.json        ciphertext record, version N
  objects/<object_id>/latest.json      {"object_id": ..., "latest_version": N}
  updates/<object_id>/tk_v<N>.json     update key that turns vN into v(N+1)

Store spec strings accepted by make_store():
  "s3://bucket[/prefix]"  -> S3Store
  anything else           -> FileStore(directory)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

MPK_KEY = "config/mpk.json"


def record_key(object_id: str, version: int) -> str:
    return f"objects/{object_id}/v{int(version)}.json"


def latest_key(object_id: str) -> str:
    return f"objects/{object_id}/latest.json"


def update_key_key(object_id: str, base_version: int) -> str:
    return f"updates/{object_id}/tk_v{int(base_version)}.json"


UPDATE_KEY_RE = re.compile(r"(?:^|/)updates/(?P<oid>[^/]+)/tk_v(?P<ver>\d+)\.json$")


class _BaseStore:
    def put_json(self, key: str, obj: Any) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def get_json(self, key: str) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    def exists(self, key: str) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def delete(self, key: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    # ---- record helpers ----
    def put_record(self, record: Dict[str, Any]) -> str:
        oid, ver = record["object_id"], int(record["version"])
        key = record_key(oid, ver)
        if self.exists(key):
            raise FileExistsError(f"{key} already exists; versions are immutable.")
        self.put_json(key, record)
        self.put_json(latest_key(oid), {"object_id": oid, "latest_version": ver})
        return key

    def latest_version(self, object_id: str) -> int:
        return int(self.get_json(latest_key(object_id))["latest_version"])

    def get_record(self, object_id: str, version: Optional[int] = None) -> Dict[str, Any]:
        if version is None:
            version = self.latest_version(object_id)
        return self.get_json(record_key(object_id, version))


class FileStore(_BaseStore):
    def __init__(self, root_dir: str):
        self.root = Path(root_dir)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        p = (self.root / key).resolve()
        if self.root.resolve() not in p.parents:
            raise ValueError(f"Key escapes store root: {key}")
        return p

    def put_json(self, key: str, obj: Any) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(p)

    def get_json(self, key: str) -> Any:
        p = self._path(key)
        if not p.exists():
            raise FileNotFoundError(f"Not found in store: {key}")
        return json.loads(p.read_text(encoding="utf-8"))

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def delete(self, key: str) -> None:
        p = self._path(key)
        if p.exists():
            p.unlink()

    def __repr__(self) -> str:
        return f"FileStore({self.root})"


class S3Store(_BaseStore):
    def __init__(self, bucket: str, prefix: str = "", client: Any = None):
        if client is None:
            import boto3
            client = boto3.client("s3")
        self.s3 = client
        self.bucket = bucket
        self.prefix = prefix.strip("/")

    def _k(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def put_json(self, key: str, obj: Any) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.s3.put_object(Bucket=self.bucket, Key=self._k(key), Body=body, ContentType="application/json")

    def get_json(self, key: str) -> Any:
        try:
            body = self.s3.get_object(Bucket=self.bucket, Key=self._k(key))["Body"].read()
        except self.s3.exceptions.NoSuchKey as e:
            raise FileNotFoundError(f"Not found in s3://{self.bucket}/{self._k(key)}") from e
        return json.loads(body)

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError
        try:
            self.s3.head_object(Bucket=self.bucket, Key=self._k(key))
            return True
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def delete(self, key: str) -> None:
        self.s3.delete_object(Bucket=self.bucket, Key=self._k(key))

    def __repr__(self) -> str:
        return f"S3Store(s3://{self.bucket}/{self.prefix})"


def make_store(spec: str, s3_client: Any = None) -> _BaseStore:
    if spec.startswith("s3://"):
        rest = spec[len("s3://"):]
        bucket, _, prefix = rest.partition("/")
        return S3Store(bucket, prefix, client=s3_client)
    return FileStore(spec)
